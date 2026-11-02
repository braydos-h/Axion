use crate::{
    packet::{Packet, Protocol},
    tls::{parse_client_hello, TlsInfo},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flow {
    pub id: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: Protocol,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packet_size_sum: u64,
    pub packet_size_min: u32,
    pub packet_size_max: u32,
    pub packet_size_buckets: [u64; 5],
    pub inter_arrival_sum_ms: u64,
    pub inter_arrival_count: u64,
    pub tcp_syn: bool,
    pub tcp_syn_ack: bool,
    pub tcp_ack: bool,
    pub tls: Option<TlsInfo>,
}
impl Flow {
    pub fn duration_ms(&self) -> u64 {
        self.last_seen_ms.saturating_sub(self.first_seen_ms)
    }
}
#[derive(Hash, Eq, PartialEq, Clone, Copy)]
struct Key {
    a: SocketAddr,
    b: SocketAddr,
    protocol: Protocol,
}
impl Key {
    fn new(p: &Packet) -> Self {
        let (a, b) = if p.src <= p.dst {
            (p.src, p.dst)
        } else {
            (p.dst, p.src)
        };
        Self {
            a,
            b,
            protocol: p.protocol,
        }
    }
}
#[derive(Default)]
struct Stream {
    expected: Option<u32>,
    bytes: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    stopped: bool,
}
impl Stream {
    fn add(&mut self, seq: u32, syn: bool, data: &[u8]) -> Option<TlsInfo> {
        const LIMIT: usize = 65536;
        if self.stopped {
            return None;
        }
        let start = seq.wrapping_add(u32::from(syn));
        if self.expected.is_none() && (syn || !data.is_empty()) {
            self.expected = Some(start);
        }
        if data.is_empty() {
            return None;
        }
        let expected = self.expected?;
        let offset = start.wrapping_sub(expected) as i32;
        if offset > 0 {
            if self.pending.len() < 32 && self.pending_bytes.saturating_add(data.len()) <= LIMIT {
                if !self.pending.contains_key(&start) {
                    self.pending_bytes += data.len();
                    self.pending.insert(start, data.to_vec());
                }
            } else {
                self.stopped = true;
                self.pending.clear();
                self.bytes.clear();
            }
            return None;
        }
        let overlap = expected.wrapping_sub(start) as usize;
        if overlap < data.len() {
            self.append(&data[overlap..]);
        }
        // Drain in-order buffered segments. Retransmitted overlaps are harmless.
        while let Some((&first, _)) = self.pending.first_key_value() {
            let expected = self.expected?;
            if first.wrapping_sub(expected) as i32 > 0 {
                break;
            }
            let part = self.pending.remove(&first)?;
            self.pending_bytes -= part.len();
            let overlap = expected.wrapping_sub(first) as usize;
            if overlap < part.len() {
                self.append(&part[overlap..]);
            }
        }
        if self.stopped {
            return None;
        }
        if let Some(info) = parse_client_hello(&self.bytes) {
            self.stopped = true;
            self.bytes.clear();
            self.pending.clear();
            return Some(info);
        }
        // Do not retain arbitrary traffic indefinitely when its first record is not a TLS handshake.
        if self.bytes.first().is_some_and(|b| *b != 22) {
            self.stopped = true;
            self.bytes.clear();
            self.pending.clear();
        }
        None
    }
    fn append(&mut self, data: &[u8]) {
        if self.bytes.len().saturating_add(data.len()) > 65536 {
            self.stopped = true;
            self.bytes.clear();
            self.pending.clear();
            return;
        }
        self.bytes.extend_from_slice(data);
        self.expected = self.expected.map(|s| s.wrapping_add(data.len() as u32));
    }
}
struct Tracked {
    flow: Flow,
    forward: Stream,
    reverse: Stream,
}
pub struct FlowTable {
    flows: HashMap<Key, Tracked>,
    max_flows: usize,
    timeout_ms: u64,
    next_id: u64,
}
impl FlowTable {
    pub fn new(max_flows: usize, timeout_ms: u64) -> Self {
        Self {
            flows: HashMap::new(),
            max_flows: max_flows.max(1),
            timeout_ms,
            next_id: 1,
        }
    }
    pub fn len(&self) -> usize {
        self.flows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.flows.len();
        self.flows
            .retain(|_, v| now_ms.saturating_sub(v.flow.last_seen_ms) < self.timeout_ms);
        before - self.flows.len()
    }
    pub fn snapshots(&self) -> Vec<Flow> {
        self.flows.values().map(|f| f.flow.clone()).collect()
    }
    pub fn ingest(&mut self, p: Packet) -> Flow {
        let key = Key::new(&p);
        if !self.flows.contains_key(&key) {
            if self.flows.len() >= self.max_flows {
                if let Some(old) = self
                    .flows
                    .iter()
                    .min_by_key(|(_, f)| f.flow.last_seen_ms)
                    .map(|(k, _)| *k)
                {
                    self.flows.remove(&old);
                }
            }
            let flow = Flow {
                id: self.next_id,
                src: p.src,
                dst: p.dst,
                protocol: p.protocol,
                first_seen_ms: p.timestamp_ms,
                last_seen_ms: p.timestamp_ms,
                packets_sent: 0,
                packets_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                packet_size_sum: 0,
                packet_size_min: u32::MAX,
                packet_size_max: 0,
                packet_size_buckets: [0; 5],
                inter_arrival_sum_ms: 0,
                inter_arrival_count: 0,
                tcp_syn: false,
                tcp_syn_ack: false,
                tcp_ack: false,
                tls: None,
            };
            self.next_id = self.next_id.saturating_add(1);
            self.flows.insert(
                key,
                Tracked {
                    flow,
                    forward: Stream::default(),
                    reverse: Stream::default(),
                },
            );
        }
        let tracked = self.flows.get_mut(&key).expect("inserted flow");
        let f = &mut tracked.flow;
        let forward = p.src == f.src && p.dst == f.dst;
        if f.packets_sent + f.packets_received > 0 {
            f.inter_arrival_sum_ms = f
                .inter_arrival_sum_ms
                .saturating_add(p.timestamp_ms.saturating_sub(f.last_seen_ms));
            f.inter_arrival_count += 1;
        }
        f.first_seen_ms = f.first_seen_ms.min(p.timestamp_ms);
        f.last_seen_ms = f.last_seen_ms.max(p.timestamp_ms);
        if forward {
            f.packets_sent += 1;
            f.bytes_sent += p.wire_len as u64;
        } else {
            f.packets_received += 1;
            f.bytes_received += p.wire_len as u64;
        }
        f.packet_size_sum += p.wire_len as u64;
        f.packet_size_min = f.packet_size_min.min(p.wire_len);
        f.packet_size_max = f.packet_size_max.max(p.wire_len);
        let bucket = match p.wire_len {
            0..=127 => 0,
            128..=511 => 1,
            512..=1023 => 2,
            1024..=1518 => 3,
            _ => 4,
        };
        f.packet_size_buckets[bucket] += 1;
        if p.protocol == Protocol::Tcp {
            let syn = p.tcp_flags & 2 != 0;
            let ack = p.tcp_flags & 16 != 0;
            f.tcp_syn |= syn && !ack;
            f.tcp_syn_ack |= syn && ack;
            f.tcp_ack |= ack && !syn;
            if f.tls.is_none() {
                if let Some(seq) = p.tcp_seq {
                    let stream = if forward {
                        &mut tracked.forward
                    } else {
                        &mut tracked.reverse
                    };
                    f.tls = stream.add(seq, syn, &p.payload);
                }
            }
        }
        f.clone()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn packet(src: &str, dst: &str, time: u64) -> Packet {
        Packet {
            timestamp_ms: time,
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            protocol: Protocol::Tcp,
            wire_len: 100,
            tcp_seq: Some(1),
            tcp_flags: 0,
            payload: Vec::new(),
        }
    }
    #[test]
    fn bidirectional_and_expiry() {
        let mut t = FlowTable::new(2, 1000);
        let a = t.ingest(packet("10.0.0.1:4000", "10.0.0.2:443", 100));
        let b = t.ingest(packet("10.0.0.2:443", "10.0.0.1:4000", 200));
        assert_eq!(a.id, b.id);
        assert_eq!((b.packets_sent, b.packets_received), (1, 1));
        assert_eq!(b.duration_ms(), 100);
        assert_eq!(t.expire(1199), 0);
        assert_eq!(t.expire(1200), 1);
    }
    #[test]
    fn reassembles_out_of_order_and_retransmit() {
        let mut s = Stream::default();
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.extend([0, 0, 2, 0x13, 1, 1, 0, 0, 0]);
        let mut h = vec![1, 0, 0, body.len() as u8];
        h.extend(body);
        let mut r = vec![22, 3, 3, 0, h.len() as u8];
        r.extend(h);
        s.add(99, true, &[]);
        assert!(s.add(110, false, &r[10..]).is_none());
        assert!(s.add(100, false, &r[..10]).is_some());
    }
}
