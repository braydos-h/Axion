//! Stateful bidirectional flow tracking with bounded TCP reassembly.

pub mod reassembly;

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use parking_lot::Mutex;
use serde::Serialize;

use crate::dpi::FlowAnalysis;
use crate::packet::{IpProtocol, PacketView, L4};
use crate::rules::Decision;
use reassembly::TcpReassembler;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{ip}]:{}", self.port),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub low: Endpoint,
    pub high: Endpoint,
    pub protocol: IpProtocol,
}

impl FlowKey {
    pub fn new(src: Endpoint, dst: Endpoint, protocol: IpProtocol) -> Self {
        if src <= dst {
            Self {
                low: src,
                high: dst,
                protocol,
            }
        } else {
            Self {
                low: dst,
                high: src,
                protocol,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy)]
pub struct Observation {
    pub should_analyze: bool,
    pub new_data: bool,
    pub first_packet: bool,
}

pub struct FlowState {
    pub id: u64,
    pub key: FlowKey,
    pub client: Endpoint,
    pub server: Endpoint,
    pub started_ms: u64,
    pub last_seen_ms: u64,
    pub client_packets: u64,
    pub server_packets: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub packet_sizes: [u64; 8],
    pub tcp_flags_seen: u8,
    pub client_fin: bool,
    pub server_fin: bool,
    pub saw_reset: bool,
    tcp: [TcpReassembler; 2],
    datagrams: [Vec<u8>; 2],
    pub analysis: Option<FlowAnalysis>,
    analyzed_client_len: usize,
    analyzed_server_len: usize,
    last_analysis_ms: u64,
    pub decision: Option<Decision>,
    pub blocked: bool,
    pub detection_fingerprint: u64,
    pub event_fingerprint: u64,
    pub detections_emitted: u64,
    pub policy_version: u64,
    pub packets: u64,
}

impl FlowState {
    fn new(
        id: u64,
        key: FlowKey,
        client: Endpoint,
        server: Endpoint,
        now_ms: u64,
        max_reassembly: usize,
    ) -> Self {
        Self {
            id,
            key,
            client,
            server,
            started_ms: now_ms,
            last_seen_ms: now_ms,
            client_packets: 0,
            server_packets: 0,
            client_bytes: 0,
            server_bytes: 0,
            packet_sizes: [0; 8],
            tcp_flags_seen: 0,
            client_fin: false,
            server_fin: false,
            saw_reset: false,
            tcp: [
                TcpReassembler::new(max_reassembly),
                TcpReassembler::new(max_reassembly),
            ],
            datagrams: [Vec::new(), Vec::new()],
            analysis: None,
            analyzed_client_len: 0,
            analyzed_server_len: 0,
            last_analysis_ms: 0,
            decision: None,
            blocked: false,
            detection_fingerprint: 0,
            event_fingerprint: 0,
            detections_emitted: 0,
            policy_version: 0,
            packets: 0,
        }
    }

    pub fn direction(&self, src: &Endpoint) -> Direction {
        if *src == self.client {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        }
    }

    pub fn observe(
        &mut self,
        packet: &PacketView<'_>,
        wire_len: usize,
        now_ms: u64,
    ) -> Observation {
        let first_packet = self.packets == 0;
        self.packets = self.packets.saturating_add(1);
        self.last_seen_ms = now_ms;
        let src = Endpoint::new(packet.src, packet.src_port());
        let direction = self.direction(&src);
        let idx = match direction {
            Direction::ClientToServer => 0,
            Direction::ServerToClient => 1,
        };
        if idx == 0 {
            self.client_packets = self.client_packets.saturating_add(1);
            self.client_bytes = self.client_bytes.saturating_add(wire_len as u64);
        } else {
            self.server_packets = self.server_packets.saturating_add(1);
            self.server_bytes = self.server_bytes.saturating_add(wire_len as u64);
        }
        self.packet_sizes[packet_bucket(wire_len)] += 1;

        let mut new_data = false;
        if let L4::Tcp(tcp) = &packet.l4 {
            self.tcp_flags_seen |= tcp.flags.0;
            if tcp.flags.fin() {
                if idx == 0 {
                    self.client_fin = true;
                } else {
                    self.server_fin = true;
                }
            }
            if tcp.flags.rst() {
                self.saw_reset = true;
            }
            if tcp.flags.syn() {
                self.tcp[idx].observe_syn(tcp.seq);
            }
            if !tcp.payload.is_empty() {
                let seq = if tcp.flags.syn() {
                    tcp.seq.wrapping_add(1)
                } else {
                    tcp.seq
                };
                new_data = self.tcp[idx].push(seq, tcp.payload);
            }
        } else if !matches!(&packet.l4, L4::Icmp(_)) {
            let payload = packet.payload();
            let slot = &mut self.datagrams[idx];
            if slot.is_empty() && !payload.is_empty() {
                let take = payload.len().min(crate::protocols::MAX_INSPECT_BYTES);
                slot.extend_from_slice(&payload[..take]);
                new_data = true;
            }
        }

        let client_len = self.client_payload().len();
        let server_len = self.server_payload().len();
        let should_analyze = self.should_analyze(client_len, server_len, now_ms);
        Observation {
            should_analyze,
            new_data,
            first_packet,
        }
    }

    fn should_analyze(&self, client_len: usize, server_len: usize, now_ms: u64) -> bool {
        if self.blocked {
            return false;
        }
        if self.key.protocol != IpProtocol::TCP && self.key.protocol != IpProtocol::UDP {
            return false;
        }
        if client_len == 0 && server_len == 0 {
            return false;
        }
        let Some(analysis) = &self.analysis else {
            return true;
        };
        let total = client_len + server_len;
        let analyzed = self.analyzed_client_len + self.analyzed_server_len;
        if total <= analyzed {
            return false;
        }
        let growth = total - analyzed;
        // A truncated TLS record/HTTP header must be re-evaluated as soon as
        // the next contiguous bytes arrive, even if a partial finding was
        // already produced (for example a TLS record without its SNI yet).
        if analysis.incomplete && growth >= 8 {
            return true;
        }
        // Handshake parsers need the full first flight; protocol changes (for
        // example a DNS response) arrive in the reverse direction.
        if analysis.max_confidence < 0.90 && growth >= 32 {
            return true;
        }
        if growth >= 1024 {
            return true;
        }
        now_ms.saturating_sub(self.last_analysis_ms) >= 2_000 && growth > 0
    }

    pub fn client_payload(&self) -> &[u8] {
        match self.key.protocol {
            IpProtocol::TCP => self.tcp[0].data(),
            IpProtocol::UDP => &self.datagrams[0],
            _ => &self.datagrams[0],
        }
    }

    pub fn server_payload(&self) -> &[u8] {
        match self.key.protocol {
            IpProtocol::TCP => self.tcp[1].data(),
            IpProtocol::UDP => &self.datagrams[1],
            _ => &self.datagrams[1],
        }
    }

    pub fn apply_analysis(
        &mut self,
        analysis: FlowAnalysis,
        client_len: usize,
        server_len: usize,
        now_ms: u64,
    ) {
        self.analyzed_client_len = client_len;
        self.analyzed_server_len = server_len;
        self.last_analysis_ms = now_ms;
        self.analysis = Some(analysis);
    }

    pub fn set_decision(&mut self, decision: Decision) {
        self.blocked = decision.action.is_blocking();
        self.decision = Some(decision);
    }

    pub fn duration_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.started_ms)
    }

    pub fn is_terminated(&self) -> bool {
        self.saw_reset || (self.client_fin && self.server_fin)
    }

    pub fn snapshot(&self, now_ms: u64) -> FlowSnapshot {
        let analysis = self.analysis.as_ref();
        let decision = self.decision.as_ref();
        FlowSnapshot {
            id: self.id,
            client: self.client.to_string(),
            server: self.server.to_string(),
            protocol: self.key.protocol.to_string(),
            started_ms: self.started_ms,
            last_seen_ms: self.last_seen_ms,
            duration_ms: self.duration_ms(now_ms),
            packets: self.packets,
            client_packets: self.client_packets,
            server_packets: self.server_packets,
            client_bytes: self.client_bytes,
            server_bytes: self.server_bytes,
            total_bytes: self.client_bytes + self.server_bytes,
            packet_sizes: self.packet_sizes,
            detected_protocols: analysis
                .map(|a| a.detected_protocols.clone())
                .unwrap_or_default(),
            primary_protocol: analysis.and_then(|a| a.primary_protocol.clone()),
            confidence: analysis.map(|a| a.max_confidence).unwrap_or(0.0),
            proxy_score: analysis.map(|a| a.proxy_score).unwrap_or(0.0),
            incomplete: analysis.map(|a| a.incomplete).unwrap_or(false),
            sni: analysis.and_then(|a| a.sni.clone()),
            alpn: analysis.map(|a| a.alpn.clone()).unwrap_or_default(),
            dns_names: analysis.map(|a| a.dns_names.clone()).unwrap_or_default(),
            tls_ja3: analysis
                .and_then(|a| a.tls.as_ref())
                .and_then(|t| t.ja3_hash.clone()),
            tls_version: analysis.and_then(|a| a.tls_version.clone()),
            tls_cipher_count: analysis.map(|a| a.tls_cipher_count).unwrap_or(0),
            tls_extension_count: analysis.map(|a| a.tls_extension_count).unwrap_or(0),
            tls_grease_count: analysis.map(|a| a.tls_grease_count).unwrap_or(0),
            tls_ech_present: analysis.map(|a| a.tls_ech_present).unwrap_or(false),
            http_method: analysis.and_then(|a| a.http_method.clone()),
            http_host: analysis.and_then(|a| a.http_host.clone()),
            http_target: analysis.and_then(|a| a.http_target.clone()),
            dns_qtype: analysis.and_then(|a| a.dns_qtype.clone()),
            categories: analysis
                .map(|a| a.category_scores.clone())
                .unwrap_or_default(),
            evidence: analysis.map(|a| a.evidence.clone()).unwrap_or_default(),
            action: decision
                .map(|d| d.action.to_string())
                .unwrap_or_else(|| "allow".to_string()),
            matched_rule: decision.and_then(|d| d.matched_rule.clone()),
            blocked: self.blocked,
            closed: self.is_terminated(),
        }
    }
}

fn packet_bucket(len: usize) -> usize {
    match len {
        0..=63 => 0,
        64..=127 => 1,
        128..=255 => 2,
        256..=511 => 3,
        512..=1023 => 4,
        1024..=1499 => 5,
        1500..=8999 => 6,
        _ => 7,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowSnapshot {
    pub id: u64,
    pub client: String,
    pub server: String,
    pub protocol: String,
    pub started_ms: u64,
    pub last_seen_ms: u64,
    pub duration_ms: u64,
    pub packets: u64,
    pub client_packets: u64,
    pub server_packets: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub total_bytes: u64,
    pub packet_sizes: [u64; 8],
    pub detected_protocols: Vec<String>,
    pub primary_protocol: Option<String>,
    pub confidence: f32,
    pub proxy_score: f32,
    pub incomplete: bool,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub dns_names: Vec<String>,
    pub tls_ja3: Option<String>,
    pub tls_version: Option<String>,
    pub tls_cipher_count: usize,
    pub tls_extension_count: usize,
    pub tls_grease_count: usize,
    pub tls_ech_present: bool,
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_target: Option<String>,
    pub dns_qtype: Option<String>,
    pub categories: BTreeMap<String, f32>,
    pub evidence: Vec<String>,
    pub action: String,
    pub matched_rule: Option<String>,
    pub blocked: bool,
    pub closed: bool,
}

pub struct FlowEntry {
    pub state: Mutex<FlowState>,
    pub last_seen_ms: AtomicU64,
    terminated: AtomicBool,
}

impl FlowEntry {
    pub fn touch(&self, now_ms: u64) {
        self.last_seen_ms.store(now_ms, Ordering::Relaxed);
    }

    pub fn last_seen(&self) -> u64 {
        self.last_seen_ms.load(Ordering::Relaxed)
    }

    pub fn mark_terminated(&self) {
        self.terminated.store(true, Ordering::Relaxed);
    }

    pub fn terminated(&self) -> bool {
        self.terminated.load(Ordering::Relaxed)
    }
}

pub struct FlowTable {
    flows: DashMap<FlowKey, Arc<FlowEntry>>,
    max_flows: usize,
    max_reassembly: usize,
    next_id: AtomicU64,
    evictions: AtomicU64,
}

impl FlowTable {
    pub fn new(max_flows: usize, max_reassembly: usize) -> Self {
        Self {
            flows: DashMap::with_capacity(max_flows.min(16_384)),
            max_flows: max_flows.max(16),
            max_reassembly,
            next_id: AtomicU64::new(1),
            evictions: AtomicU64::new(0),
        }
    }

    pub fn get_or_create(&self, packet: &PacketView<'_>, now_ms: u64) -> (Arc<FlowEntry>, bool) {
        let src = Endpoint::new(packet.src, packet.src_port());
        let dst = Endpoint::new(packet.dst, packet.dst_port());
        let key = FlowKey::new(src, dst, packet.protocol);
        if let Some(entry) = self.flows.get(&key) {
            return (Arc::clone(entry.value()), false);
        }
        if self.flows.len() >= self.max_flows {
            self.evict_oldest();
        }
        let client = src;
        let server = dst;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut created = false;
        let state = FlowState::new(id, key, client, server, now_ms, self.max_reassembly);
        let entry = self
            .flows
            .entry(key)
            .or_insert_with(|| {
                created = true;
                Arc::new(FlowEntry {
                    state: Mutex::new(state),
                    last_seen_ms: AtomicU64::new(now_ms),
                    terminated: AtomicBool::new(false),
                })
            })
            .value()
            .clone();
        (entry, created)
    }

    pub fn active_flows(&self) -> usize {
        self.flows.len()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    pub fn gc(&self, now_ms: u64, idle_timeout_ms: u64) -> usize {
        let before = self.flows.len();
        self.flows.retain(|_, entry| {
            let timeout = if entry.terminated() {
                2_000
            } else {
                idle_timeout_ms
            };
            now_ms.saturating_sub(entry.last_seen()) < timeout
        });
        let removed = before - self.flows.len();
        if removed > 0 {
            self.evictions.fetch_add(removed as u64, Ordering::Relaxed);
        }
        removed
    }

    fn evict_oldest(&self) {
        let oldest = self
            .flows
            .iter()
            .min_by_key(|entry| entry.value().last_seen())
            .map(|entry| *entry.key());
        if let Some(key) = oldest {
            if self.flows.remove(&key).is_some() {
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn clear(&self) {
        self.flows.clear();
    }

    pub fn snapshots(&self, limit: usize) -> Vec<FlowSnapshot> {
        let now = unix_ms();
        let mut out: Vec<FlowSnapshot> = self
            .flows
            .iter()
            .map(|entry| entry.value().state.lock().snapshot(now))
            .collect();
        out.sort_by_key(|f| std::cmp::Reverse(f.last_seen_ms));
        out.truncate(limit);
        out
    }
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    fn tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        seq: u32,
        payload: &'static [u8],
    ) -> PacketView<'static> {
        let tcp = crate::packet::TcpSegment {
            src_port: sport,
            dst_port: dport,
            seq,
            ack: 0,
            flags: crate::packet::TcpFlags(0x18),
            window: 65535,
            payload,
        };
        PacketView {
            timestamp: Some(SystemTime::now()),
            src: IpAddr::V4(Ipv4Addr::from(src)),
            dst: IpAddr::V4(Ipv4Addr::from(dst)),
            protocol: IpProtocol::TCP,
            ttl: 64,
            vlan: None,
            l4: L4::Tcp(tcp),
            truncated: false,
        }
    }

    #[test]
    fn bidirectional_tracking_and_key_canonicalisation() {
        let table = FlowTable::new(100, 65535);
        let a = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1, b"hello");
        let b = tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 1234, 1, b"world");
        let (entry, created) = table.get_or_create(&a, 1);
        assert!(created);
        {
            let mut s = entry.state.lock();
            s.observe(&a, 60, 1);
        }
        let (entry2, created2) = table.get_or_create(&b, 2);
        assert!(!created2);
        {
            let mut s = entry2.state.lock();
            s.observe(&b, 60, 2);
            assert_eq!(s.client_payload(), b"hello");
            assert_eq!(s.server_payload(), b"world");
            assert_eq!(s.client, Endpoint::new(a.src, 1234));
        }
        let id1 = entry.state.lock().id;
        let id2 = entry2.state.lock().id;
        assert_eq!(id1, id2);
        assert_eq!(table.active_flows(), 1);
    }

    #[test]
    fn terminated_flows_are_garbage_collected_early() {
        let table = FlowTable::new(100, 65535);
        let p = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 0, b"x");
        let (entry, _) = table.get_or_create(&p, 100);
        {
            let mut s = entry.state.lock();
            s.observe(&p, 40, 100);
            assert!(!s.is_terminated());
        }
        entry.mark_terminated();
        assert_eq!(table.gc(3_500, 60_000), 1);
    }

    #[test]
    fn gc_removes_idle_flows() {
        let table = FlowTable::new(100, 65535);
        let p = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 0, b"x");
        table.get_or_create(&p, 100);
        assert_eq!(table.gc(100 + 5000, 1000), 1);
        assert_eq!(table.active_flows(), 0);
    }

    #[test]
    fn table_is_bounded() {
        let table = FlowTable::new(16, 65535);
        for i in 0..100u16 {
            let p = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1000 + i, 80, 0, b"x");
            table.get_or_create(&p, i as u64);
        }
        assert!(table.active_flows() <= 16);
    }

    #[test]
    fn snapshot_contains_metadata() {
        let table = FlowTable::new(100, 65535);
        let p = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, 0, b"x");
        let (entry, _) = table.get_or_create(&p, 100);
        {
            let mut s = entry.state.lock();
            s.observe(&p, 40, 100);
        }
        let snap = table.snapshots(10);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].client, "10.0.0.1:1");
    }
}
