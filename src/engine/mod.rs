//! The analysis pipeline shared by passive capture, NFQUEUE inline mode and
//! offline pcap inspection.

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use anyhow::{bail, Result};
use ipnet::IpNet;
use parking_lot::{Mutex, RwLock};

use crate::config::{Action, Config, Mode};
use crate::detection;
use crate::dpi::{AnalysisInput, Classifier};
use crate::flow::{unix_ms, Endpoint, FlowTable};
use crate::packet::{self, FragmentCache, LinkType, PacketView, ParseOutcome};
use crate::rules::{RuleContext, RuleStore};
use crate::telemetry::{DetectionEvent, Telemetry};

#[derive(Debug, Clone)]
pub struct ProcessingResult {
    pub action: Action,
    pub blocked: bool,
    pub matched_rule: Option<String>,
    pub flow_id: Option<u64>,
    pub reason: String,
}

impl ProcessingResult {
    fn allow(reason: impl Into<String>) -> Self {
        Self {
            action: Action::Allow,
            blocked: false,
            matched_rule: None,
            flow_id: None,
            reason: reason.into(),
        }
    }
}

pub struct Engine {
    config: Arc<Config>,
    flows: Arc<FlowTable>,
    fragments: Mutex<FragmentCache>,
    rules: Arc<RuleStore>,
    telemetry: Arc<Telemetry>,
    classifier: Classifier,
    mode: AtomicU8,
    dry_run: AtomicBool,
    can_enforce: bool,
    backend: RwLock<String>,
    capture_source: RwLock<String>,
    capture_workers: AtomicU64,
    bypass_cidrs: Vec<IpNet>,
    bypass_ports: HashSet<u16>,
}

impl Engine {
    pub fn new(
        config: Arc<Config>,
        rules: Arc<RuleStore>,
        telemetry: Arc<Telemetry>,
        can_enforce: bool,
        backend: impl Into<String>,
    ) -> Result<Arc<Self>> {
        Self::new_with_classifier(
            config,
            rules,
            telemetry,
            can_enforce,
            backend,
            Classifier::new(),
        )
    }

    pub fn new_with_classifier(
        config: Arc<Config>,
        rules: Arc<RuleStore>,
        telemetry: Arc<Telemetry>,
        can_enforce: bool,
        backend: impl Into<String>,
        classifier: Classifier,
    ) -> Result<Arc<Self>> {
        if config.general.mode == Mode::Enforce && !can_enforce {
            bail!("enforce mode requires the inline NFQUEUE backend");
        }
        let bypass_cidrs = config
            .firewall
            .bypass_cidrs
            .iter()
            .filter_map(|c| c.parse::<IpNet>().ok())
            .collect();
        let mut bypass_ports: HashSet<u16> =
            config.firewall.bypass_tcp_ports.iter().copied().collect();
        if config.api.enabled {
            bypass_ports.insert(config.api.bind.port());
        }
        let mode = match config.general.mode {
            Mode::Monitor => 0,
            Mode::Enforce => 1,
        };
        Ok(Arc::new(Self {
            flows: Arc::new(FlowTable::new(
                config.general.max_flows,
                config.general.max_reassembly_bytes,
            )),
            fragments: Mutex::new(FragmentCache::new(
                config.general.max_fragment_sets,
                config.general.max_fragment_bytes,
                std::time::Duration::from_secs(config.general.fragment_timeout_seconds),
            )),
            telemetry,
            rules,
            classifier,
            dry_run: AtomicBool::new(config.general.dry_run),
            can_enforce,
            backend: RwLock::new(backend.into()),
            capture_source: RwLock::new("none".to_string()),
            capture_workers: AtomicU64::new(0),
            bypass_cidrs,
            bypass_ports,
            mode: AtomicU8::new(mode),
            config,
        }))
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn flows(&self) -> &Arc<FlowTable> {
        &self.flows
    }

    pub fn rules(&self) -> &Arc<RuleStore> {
        &self.rules
    }

    pub fn telemetry(&self) -> &Arc<Telemetry> {
        &self.telemetry
    }

    pub fn mode(&self) -> Mode {
        if self.mode.load(Ordering::Relaxed) == 1 {
            Mode::Enforce
        } else {
            Mode::Monitor
        }
    }

    pub fn set_mode(&self, mode: Mode) -> Result<()> {
        if mode == Mode::Enforce && !self.can_enforce {
            bail!("cannot enable enforcement: NFQUEUE backend is not active");
        }
        self.mode.store(
            match mode {
                Mode::Monitor => 0,
                Mode::Enforce => 1,
            },
            Ordering::Relaxed,
        );
        Ok(())
    }

    pub fn dry_run(&self) -> bool {
        self.dry_run.load(Ordering::Relaxed)
    }

    pub fn set_dry_run(&self, value: bool) {
        self.dry_run.store(value, Ordering::Relaxed);
    }

    pub fn can_enforce(&self) -> bool {
        self.can_enforce
    }

    pub fn backend(&self) -> String {
        self.backend.read().clone()
    }

    pub fn set_backend(&self, backend: impl Into<String>) {
        *self.backend.write() = backend.into();
    }

    pub fn set_capture_info(&self, source: impl Into<String>, workers: usize) {
        *self.capture_source.write() = source.into();
        self.capture_workers
            .store(workers as u64, Ordering::Relaxed);
    }

    pub fn capture_source(&self) -> String {
        self.capture_source.read().clone()
    }

    pub fn capture_workers(&self) -> usize {
        self.capture_workers.load(Ordering::Relaxed) as usize
    }

    pub fn enforcement_active(&self) -> bool {
        self.can_enforce && self.mode() == Mode::Enforce && !self.dry_run()
    }

    /// Process an Ethernet (or other pcap link-type) frame.
    pub fn process_link_frame(
        &self,
        link_type: LinkType,
        data: &[u8],
        timestamp: Option<SystemTime>,
    ) -> ProcessingResult {
        self.telemetry.metrics.record_packet(data.len());
        let outcome = packet::parse_link_frame(link_type, data, timestamp);
        let (result, event) = self.handle_outcome(outcome, data.len());
        self.finish(result, event)
    }

    /// Process a raw L3 packet, as delivered by NFQUEUE.
    pub fn process_l3_frame(&self, data: &[u8], timestamp: Option<SystemTime>) -> ProcessingResult {
        self.telemetry.metrics.record_packet(data.len());
        let outcome = packet::parse_l3(data, timestamp);
        let (result, event) = self.handle_outcome(outcome, data.len());
        self.finish(result, event)
    }

    fn finish(&self, result: ProcessingResult, event: Option<DetectionEvent>) -> ProcessingResult {
        self.telemetry.metrics.record_verdict(result.blocked);
        if let Some(event) = event {
            self.telemetry.metrics.record_detection();
            if self.config.telemetry.log_detections {
                if event.blocked {
                    tracing::warn!(
                        flow_id = event.flow_id,
                        src = %event.src,
                        dst = %event.dst,
                        protocols = ?event.protocols,
                        confidence = event.confidence,
                        rule = ?event.matched_rule,
                        "blocked traffic"
                    );
                } else {
                    tracing::info!(
                        flow_id = event.flow_id,
                        src = %event.src,
                        dst = %event.dst,
                        protocols = ?event.protocols,
                        confidence = event.confidence,
                        action = %event.action,
                        sni = ?event.sni,
                        "detection event"
                    );
                }
            }
            self.telemetry.events.push(event);
        }
        result
    }

    fn handle_outcome(
        &self,
        outcome: ParseOutcome<'_>,
        wire_len: usize,
    ) -> (ProcessingResult, Option<DetectionEvent>) {
        match outcome {
            ParseOutcome::Packet(packet) => self.process_packet(&packet, wire_len),
            ParseOutcome::Fragment(fragment) => {
                let complete = {
                    let mut cache = self.fragments.lock();
                    cache.insert(&fragment, Instant::now())
                };
                if let Some(reassembled) = complete {
                    if let ParseOutcome::Packet(packet) = packet::parse_reassembled(&reassembled) {
                        return self.process_packet(&packet, wire_len);
                    }
                }
                (ProcessingResult::allow("fragment pending"), None)
            }
            ParseOutcome::Unsupported(_) => (ProcessingResult::allow("unsupported frame"), None),
            ParseOutcome::Malformed(err) => {
                self.telemetry.metrics.record_parse_error();
                (
                    ProcessingResult::allow(format!("malformed packet: {err}")),
                    None,
                )
            }
        }
    }

    fn process_packet(
        &self,
        packet: &PacketView<'_>,
        wire_len: usize,
    ) -> (ProcessingResult, Option<DetectionEvent>) {
        if self.is_bypassed(packet.src, packet.dst, packet.src_port(), packet.dst_port()) {
            return (ProcessingResult::allow("management/allowlist bypass"), None);
        }

        let now = unix_ms();
        let (entry, _created) = self.flows.get_or_create(packet, now);
        let mut state = entry.state.lock();
        entry.touch(now);
        let rules = self.rules.current();
        let policy_version = self.rules.version();
        if state.policy_version != policy_version {
            // A successful hot reload starts a new policy generation. Existing
            // flows are re-evaluated instead of inheriting a stale verdict.
            state.policy_version = policy_version;
            state.blocked = false;
            state.decision = None;
        }
        let previous_fingerprint = state.detection_fingerprint;
        let observation = state.observe(packet, wire_len, now);
        if state.is_terminated() {
            entry.mark_terminated();
        }
        let mut analysis_changed = false;
        let mut current_fingerprint = previous_fingerprint;

        if observation.should_analyze {
            let client_len = state.client_payload().len();
            let server_len = state.server_payload().len();
            let analysis = {
                let input = AnalysisInput {
                    client_payload: state.client_payload(),
                    server_payload: state.server_payload(),
                    client_port: state.client.port,
                    server_port: state.server.port,
                    transport: state.key.protocol,
                    duration_ms: state.duration_ms(now),
                    client_bytes: state.client_bytes,
                    server_bytes: state.server_bytes,
                };
                self.classifier.analyze(input, &self.config.detection)
            };
            current_fingerprint = detection::fingerprint(&analysis);
            analysis_changed = current_fingerprint != previous_fingerprint;
            state.apply_analysis(analysis, client_len, server_len, now);
        }

        // Assessment/fingerprinting is only needed when classification changed;
        // the per-packet hot path reuses the cached fingerprint.
        let assessment = if analysis_changed {
            state.analysis.as_ref().map(|analysis| {
                detection::assess(
                    analysis,
                    rules.detection_enabled(),
                    self.config.general.monitor_confidence,
                )
            })
        } else {
            None
        };

        let src_endpoint = Endpoint::new(packet.src, packet.src_port());
        let direction = state.direction(&src_endpoint);
        let empty_protocols: Vec<String> = Vec::new();
        let empty_categories: BTreeMap<String, f32> = BTreeMap::new();
        let empty_names: Vec<String> = Vec::new();
        let (protocols, categories, confidence, sni, dns_names, total_bytes, duration_ms) =
            match state.analysis.as_ref() {
                Some(analysis) => (
                    &analysis.detected_protocols,
                    &analysis.category_scores,
                    analysis.max_confidence,
                    analysis.sni.as_deref(),
                    &analysis.dns_names,
                    state.client_bytes + state.server_bytes,
                    state.duration_ms(now),
                ),
                None => (
                    &empty_protocols,
                    &empty_categories,
                    0.0,
                    None,
                    &empty_names,
                    state.client_bytes + state.server_bytes,
                    state.duration_ms(now),
                ),
            };
        let mut decision = rules.evaluate(&RuleContext {
            src: packet.src,
            dst: packet.dst,
            src_port: packet.src_port(),
            dst_port: packet.dst_port(),
            transport: state.key.protocol,
            direction,
            protocols,
            categories,
            confidence,
            sni,
            dns_names,
            total_bytes,
            duration_ms,
            proxy_score: state
                .analysis
                .as_ref()
                .map(|a| a.proxy_score)
                .unwrap_or(0.0),
            proxy_transport_score: state
                .analysis
                .as_ref()
                .map(|a| a.proxy_transport_score)
                .unwrap_or(0.0),
            obfuscation_score: state
                .analysis
                .as_ref()
                .map(|a| a.obfuscation_score)
                .unwrap_or(0.0),
        });

        let enforcement = self.enforcement_active();
        // A flow-level block is sticky in the direction sense: reverse packets
        // must not silently re-open a flow when a direction-scoped rule no
        // longer matches. Explicit ALLOW rules/global allowlists may override.
        let explicit_allow = decision.action == Action::Allow && decision.matched_rule.is_some();
        if enforcement && state.blocked && !explicit_allow && !decision.action.is_blocking() {
            if let Some(previous) = state.decision.clone() {
                decision = previous;
            }
        }
        let effective_blocked = enforcement && decision.action.is_blocking();
        let was_blocked = state.blocked;
        let security_new = assessment
            .as_ref()
            .map(|a| a.should_emit && current_fingerprint != previous_fingerprint)
            .unwrap_or(false);
        let action_wants_event =
            decision.log || matches!(decision.action, Action::Log | Action::Monitor);
        let blocking_decision = decision.action.is_blocking();
        let newly_blocked = effective_blocked && !was_blocked;
        let event_hash = if security_new || action_wants_event || blocking_decision {
            let mut hash = current_fingerprint;
            hash = mix_hash(hash, decision.matched_rule.as_deref().unwrap_or("default"));
            hash = mix_hash(hash, &decision.action.to_string());
            if effective_blocked {
                hash ^= 1;
            }
            hash
        } else {
            state.event_fingerprint
        };
        let rule_log_new = action_wants_event && event_hash != state.event_fingerprint;
        let would_block_new =
            !enforcement && blocking_decision && event_hash != state.event_fingerprint;
        let emit = security_new || rule_log_new || newly_blocked || would_block_new;

        let event = if emit {
            let analysis = state.analysis.as_ref();
            let mut evidence: Vec<String> = analysis
                .map(|a| a.evidence.iter().take(12).cloned().collect())
                .unwrap_or_default();
            if !evidence.iter().any(|e| e == &decision.reason) {
                evidence.push(decision.reason.clone());
            }
            let mut protocols = analysis
                .map(|a| a.detected_protocols.clone())
                .unwrap_or_default();
            if protocols.is_empty() {
                if let Some(primary) = analysis.and_then(|a| a.primary_protocol.clone()) {
                    protocols.push(primary);
                }
            }
            let categories = analysis
                .map(|a| {
                    a.category_scores
                        .iter()
                        .filter(|(_, score)| **score > 0.0)
                        .map(|(name, _)| name.clone())
                        .collect()
                })
                .unwrap_or_default();
            let confidence = assessment
                .as_ref()
                .map(|a| {
                    if a.security_relevant {
                        a.security_confidence
                    } else {
                        analysis.map(|x| x.max_confidence).unwrap_or(0.0)
                    }
                })
                .unwrap_or(0.0);
            Some(DetectionEvent {
                id: 0,
                ts_ms: now,
                flow_id: state.id,
                src: packet.src.to_string(),
                dst: packet.dst.to_string(),
                src_port: packet.src_port(),
                dst_port: packet.dst_port(),
                transport: state.key.protocol.to_string(),
                protocols,
                categories,
                confidence,
                proxy_score: analysis.map(|a| a.proxy_score).unwrap_or(0.0),
                evidence,
                matched_rule: decision.matched_rule.clone(),
                action: decision.action.to_string(),
                blocked: effective_blocked,
                mode: self.mode().to_string(),
                sni: analysis.and_then(|a| a.sni.clone()),
                dns_names: analysis.map(|a| a.dns_names.clone()).unwrap_or_default(),
            })
        } else {
            None
        };

        if analysis_changed {
            self.telemetry.metrics.record_protocols(protocols);
            state.detection_fingerprint = current_fingerprint;
        }
        if emit {
            state.event_fingerprint = event_hash;
            state.detections_emitted = state.detections_emitted.saturating_add(1);
        }
        if newly_blocked {
            self.telemetry.metrics.record_blocked_flow();
        }
        if observation.should_analyze {
            if let Some(analysis) = state.analysis.as_mut() {
                analysis.compact();
            }
        }
        state.blocked = effective_blocked;
        state.decision = Some(decision.clone());

        let result = ProcessingResult {
            action: decision.action,
            blocked: effective_blocked,
            matched_rule: decision.matched_rule,
            flow_id: Some(state.id),
            reason: decision.reason,
        };
        (result, event)
    }

    fn is_bypassed(&self, src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> bool {
        if self.bypass_ports.contains(&src_port) || self.bypass_ports.contains(&dst_port) {
            return true;
        }
        self.bypass_cidrs
            .iter()
            .any(|net| net.contains(&src) || net.contains(&dst))
    }

    /// Periodic maintenance: flow GC, fragment expiry, rate sampling.
    pub fn maintenance(&self) {
        let now = unix_ms();
        self.flows
            .gc(now, self.config.general.flow_idle_timeout_seconds * 1000);
        self.fragments.lock().expire(Instant::now());
        let active = self.flows.active_flows();
        self.telemetry.metrics.set_active_flows(active);
        self.telemetry.metrics.sample();
    }

    pub fn snapshot_flows(&self, limit: usize) -> Vec<crate::flow::FlowSnapshot> {
        self.flows.snapshots(limit)
    }

    pub fn active_flows(&self) -> usize {
        self.flows.active_flows()
    }
}

fn mix_hash(mut hash: u64, value: &str) -> u64 {
    for byte in value.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= 0xff;
    hash.wrapping_mul(0x0000_0100_0000_01b3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::rules::RuleStore;
    use crate::telemetry::Telemetry;

    fn engine(mut config: Config) -> Arc<Engine> {
        config.firewall.bypass_cidrs.clear();
        let telemetry = Arc::new(Telemetry::new(10, 1000, 32));
        let rules = RuleStore::new("test.toml".into(), &config).unwrap();
        Engine::new(Arc::new(config), rules, telemetry, true, "test").unwrap()
    }

    fn tcp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        let tcp = &mut frame[34..54];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x18;
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn enforce_blocks_plaintext_socks5() {
        let mut config = Config::default();
        config.general.mode = Mode::Enforce;
        let engine = engine(config);
        let mut payload = vec![5, 1, 0, 5, 1, 0, 3, 11];
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&443u16.to_be_bytes());
        let frame = tcp_frame([192, 0, 2, 1], [198, 51, 100, 2], 50000, 443, &payload);
        let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
        assert!(result.blocked, "direct SOCKS5 evidence should auto-block");
        assert!(result.flow_id.is_some());
    }

    #[test]
    fn monitor_never_blocks() {
        let mut config = Config::default();
        config.general.mode = Mode::Monitor;
        let engine = engine(config);
        let mut payload = vec![5, 1, 0, 5, 1, 0, 3, 11];
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&443u16.to_be_bytes());
        let frame = tcp_frame([192, 0, 2, 1], [198, 51, 100, 2], 50000, 443, &payload);
        let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
        assert!(!result.blocked);
        assert_eq!(result.action, Action::Drop);
        assert_eq!(engine.telemetry.events.len(), 1);
    }

    #[test]
    fn benign_tls_is_allowed() {
        let config = Config::default();
        let engine = engine(config);
        let hello = crate::protocols::test_utils::client_hello(
            "www.example.com",
            &["h2", "http/1.1"],
            0x0304,
        );
        let frame = tcp_frame([192, 0, 2, 1], [198, 51, 100, 2], 50000, 443, &hello);
        let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
        assert!(!result.blocked);
        assert_eq!(engine.telemetry.events.len(), 0);
        let flows = engine.snapshot_flows(10);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].sni.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn monitor_mode_logs_would_block_even_without_log_flag() {
        use crate::config::{MatchConfig, RuleConfig};
        let mut config = Config::default();
        config.general.mode = Mode::Monitor;
        config.rules = vec![RuleConfig {
            name: "drop-443".into(),
            priority: 100,
            action: Action::Drop,
            log: false,
            enabled: true,
            matcher: MatchConfig {
                ports: vec![443],
                ..Default::default()
            },
            ..Default::default()
        }];
        let engine = engine(config);
        let hello = crate::protocols::test_utils::client_hello(
            "www.example.com",
            &["h2", "http/1.1"],
            0x0304,
        );
        let frame = tcp_frame([192, 0, 2, 1], [198, 51, 100, 2], 50000, 443, &hello);
        let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
        assert!(!result.blocked);
        assert_eq!(result.action, Action::Drop);
        assert_eq!(engine.telemetry.events.len(), 1);
    }

    #[test]
    fn bypass_accepts_management_ports() {
        let mut config = Config::default();
        config.firewall.bypass_tcp_ports = vec![8787];
        let engine = engine(config);
        let mut payload = vec![5, 1, 0, 5, 1, 0, 3, 11];
        payload.extend_from_slice(b"example.com");
        payload.extend_from_slice(&443u16.to_be_bytes());
        let frame = tcp_frame([192, 0, 2, 1], [198, 51, 100, 2], 50000, 8787, &payload);
        let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
        assert!(!result.blocked);
        assert!(result.reason.contains("bypass"));
    }

    #[test]
    fn malformed_frames_are_allowed_and_counted() {
        let engine = engine(Config::default());
        let result = engine.process_link_frame(LinkType::Ethernet, &[1, 2, 3], None);
        assert!(!result.blocked);
        let status = engine.telemetry.metrics.snapshot(0);
        assert_eq!(status.parse_errors, 1);
    }
}
