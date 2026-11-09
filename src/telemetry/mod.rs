//! Bounded telemetry: atomic counters, a rolling rate history and a ring of
//! detection events. No unbounded per-packet allocation is performed here.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct RatePoint {
    pub ts_ms: u64,
    pub pps: f64,
    pub bps: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectionEvent {
    pub id: u64,
    pub ts_ms: u64,
    pub flow_id: u64,
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: String,
    pub protocols: Vec<String>,
    pub categories: Vec<String>,
    pub confidence: f32,
    pub proxy_score: f32,
    pub evidence: Vec<String>,
    pub matched_rule: Option<String>,
    pub action: String,
    pub blocked: bool,
    pub mode: String,
    pub sni: Option<String>,
    pub dns_names: Vec<String>,
}

#[derive(Debug, Default)]
struct Sampler {
    last_packets: u64,
    last_bytes: u64,
    last_ts_ms: u64,
}

pub struct Metrics {
    started: Instant,
    started_ms: u64,
    packets_total: AtomicU64,
    bytes_total: AtomicU64,
    allowed_packets: AtomicU64,
    dropped_packets: AtomicU64,
    parse_errors: AtomicU64,
    fragment_drops: AtomicU64,
    capture_drops: AtomicU64,
    queue_drops: AtomicU64,
    enforcement_errors: AtomicU64,
    detections_total: AtomicU64,
    blocked_flows: AtomicU64,
    active_flows: AtomicU64,
    protocols: Mutex<BTreeMap<String, u64>>,
    history: Mutex<VecDeque<RatePoint>>,
    sampler: Mutex<Sampler>,
    max_history: usize,
}

impl Metrics {
    pub fn new(history_seconds: usize, sample_interval_ms: u64) -> Self {
        let interval = sample_interval_ms.max(100);
        let max_history = ((history_seconds as u64 * 1000) / interval).max(2) as usize;
        let now = now_ms();
        Self {
            started: Instant::now(),
            started_ms: now,
            packets_total: AtomicU64::new(0),
            bytes_total: AtomicU64::new(0),
            allowed_packets: AtomicU64::new(0),
            dropped_packets: AtomicU64::new(0),
            parse_errors: AtomicU64::new(0),
            fragment_drops: AtomicU64::new(0),
            capture_drops: AtomicU64::new(0),
            queue_drops: AtomicU64::new(0),
            enforcement_errors: AtomicU64::new(0),
            detections_total: AtomicU64::new(0),
            blocked_flows: AtomicU64::new(0),
            active_flows: AtomicU64::new(0),
            protocols: Mutex::new(BTreeMap::new()),
            history: Mutex::new(VecDeque::with_capacity(max_history)),
            sampler: Mutex::new(Sampler::default()),
            max_history,
        }
    }

    pub fn started_ms(&self) -> u64 {
        self.started_ms
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn record_packet(&self, wire_len: usize) {
        self.packets_total.fetch_add(1, Ordering::Relaxed);
        self.bytes_total
            .fetch_add(wire_len as u64, Ordering::Relaxed);
    }

    pub fn record_verdict(&self, blocked: bool) {
        if blocked {
            self.dropped_packets.fetch_add(1, Ordering::Relaxed);
        } else {
            self.allowed_packets.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_blocked_flow(&self) {
        self.blocked_flows.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_parse_error(&self) {
        self.parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_fragment_drop(&self) {
        self.fragment_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_capture_drop(&self) {
        self.capture_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_queue_drop(&self) {
        self.queue_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_enforcement_error(&self) {
        self.enforcement_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_detection(&self) {
        self.detections_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_active_flows(&self, value: usize) {
        self.active_flows.store(value as u64, Ordering::Relaxed);
    }

    pub fn record_protocols(&self, protocols: &[String]) {
        if protocols.is_empty() {
            return;
        }
        let mut map = self.protocols.lock();
        for protocol in protocols {
            *map.entry(protocol.clone()).or_insert(0) += 1;
        }
    }

    pub fn sample(&self) -> RatePoint {
        let now = now_ms();
        let packets = self.packets_total.load(Ordering::Relaxed);
        let bytes = self.bytes_total.load(Ordering::Relaxed);
        let mut sampler = self.sampler.lock();
        let elapsed_ms = now.saturating_sub(sampler.last_ts_ms);
        let elapsed = if elapsed_ms == 0 {
            0.001
        } else {
            elapsed_ms as f64 / 1000.0
        };
        let pps = if sampler.last_ts_ms == 0 {
            0.0
        } else {
            packets.saturating_sub(sampler.last_packets) as f64 / elapsed
        };
        let bps = if sampler.last_ts_ms == 0 {
            0.0
        } else {
            bytes.saturating_sub(sampler.last_bytes) as f64 * 8.0 / elapsed
        };
        sampler.last_packets = packets;
        sampler.last_bytes = bytes;
        sampler.last_ts_ms = now;
        let point = RatePoint {
            ts_ms: now,
            pps,
            bps,
        };
        let mut history = self.history.lock();
        history.push_back(point.clone());
        while history.len() > self.max_history {
            history.pop_front();
        }
        point
    }

    pub fn snapshot(&self, active_flows: usize) -> MetricsSnapshot {
        let (cpu_percent, memory_bytes) = process_usage(self.started.elapsed().as_secs_f64());
        let history = self.history.lock();
        let last = history.back().cloned();
        let protocols = self.protocols.lock().clone();
        MetricsSnapshot {
            uptime_seconds: self.started.elapsed().as_secs(),
            packets_total: self.packets_total.load(Ordering::Relaxed),
            bytes_total: self.bytes_total.load(Ordering::Relaxed),
            allowed_packets: self.allowed_packets.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            fragment_drops: self.fragment_drops.load(Ordering::Relaxed),
            capture_drops: self.capture_drops.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
            enforcement_errors: self.enforcement_errors.load(Ordering::Relaxed),
            detections_total: self.detections_total.load(Ordering::Relaxed),
            blocked_flows: self.blocked_flows.load(Ordering::Relaxed),
            active_flows: active_flows as u64,
            pps: last.as_ref().map(|p| p.pps).unwrap_or(0.0),
            bps: last.as_ref().map(|p| p.bps).unwrap_or(0.0),
            cpu_percent,
            memory_bytes,
            protocols,
            history: history.iter().cloned().collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub uptime_seconds: u64,
    pub packets_total: u64,
    pub bytes_total: u64,
    pub allowed_packets: u64,
    pub dropped_packets: u64,
    pub parse_errors: u64,
    pub fragment_drops: u64,
    pub capture_drops: u64,
    pub queue_drops: u64,
    pub enforcement_errors: u64,
    pub detections_total: u64,
    pub blocked_flows: u64,
    pub active_flows: u64,
    pub pps: f64,
    pub bps: f64,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub protocols: BTreeMap<String, u64>,
    pub history: Vec<RatePoint>,
}

pub struct EventLog {
    events: Mutex<VecDeque<DetectionEvent>>,
    capacity: usize,
    next_id: AtomicU64,
}

impl EventLog {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(16);
        Self {
            events: Mutex::new(VecDeque::with_capacity(capacity.min(16_384))),
            capacity,
            next_id: AtomicU64::new(1),
        }
    }

    pub fn push(&self, mut event: DetectionEvent) {
        event.id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut events = self.events.lock();
        if events.len() >= self.capacity {
            events.pop_front();
        }
        events.push_back(event);
    }

    pub fn recent(&self, limit: usize) -> Vec<DetectionEvent> {
        let events = self.events.lock();
        events.iter().rev().take(limit).cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

pub struct Telemetry {
    pub metrics: Metrics,
    pub events: EventLog,
}

impl Telemetry {
    pub fn new(history_seconds: usize, sample_interval_ms: u64, event_capacity: usize) -> Self {
        Self {
            metrics: Metrics::new(history_seconds, sample_interval_ms),
            events: EventLog::new(event_capacity),
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn process_usage(uptime_secs: f64) -> (f32, u64) {
    let mut cpu_percent = 0.0f32;
    if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
        if let Some(end) = stat.rfind(')') {
            let fields: Vec<&str> = stat[end + 1..].split_whitespace().collect();
            // After comm, field 14 (utime) and 15 (stime) are at indices 11
            // and 12 because index 0 is state (field 3).
            if fields.len() > 12 {
                let utime: u64 = fields[11].parse().unwrap_or(0);
                let stime: u64 = fields[12].parse().unwrap_or(0);
                // SAFETY: sysconf has no pointer or memory-safety
                // preconditions; _SC_CLK_TCK is a constant name.
                let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
                let ticks = if ticks > 0 { ticks as f64 } else { 100.0 };
                if uptime_secs > 0.1 {
                    cpu_percent = (((utime + stime) as f64 / ticks) / uptime_secs * 100.0) as f32;
                }
            }
        }
    }
    let mut memory_bytes = 0u64;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            if let Some(value) = line.strip_prefix("VmRSS:") {
                let kb: u64 = value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                memory_bytes = kb * 1024;
                break;
            }
        }
    }
    (cpu_percent, memory_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_rate() {
        let m = Metrics::new(60, 1000);
        m.record_packet(100);
        m.record_packet(200);
        m.record_verdict(false);
        m.record_verdict(true);
        m.record_protocols(&["tls".into(), "tls".into()]);
        let snap = m.snapshot(3);
        assert_eq!(snap.packets_total, 2);
        assert_eq!(snap.bytes_total, 300);
        assert_eq!(snap.allowed_packets, 1);
        assert_eq!(snap.dropped_packets, 1);
        assert_eq!(snap.protocols.get("tls"), Some(&2));
        assert_eq!(snap.active_flows, 3);
    }

    #[test]
    fn event_ring_is_bounded() {
        let log = EventLog::new(16);
        for i in 0..100 {
            log.push(DetectionEvent {
                id: 0,
                ts_ms: i,
                flow_id: i,
                src: "a".into(),
                dst: "b".into(),
                src_port: 1,
                dst_port: 2,
                transport: "tcp".into(),
                protocols: vec![],
                categories: vec![],
                confidence: 0.0,
                proxy_score: 0.0,
                evidence: vec![],
                matched_rule: None,
                action: "monitor".into(),
                blocked: false,
                mode: "monitor".into(),
                sni: None,
                dns_names: vec![],
            });
        }
        assert_eq!(log.len(), 16);
        let recent = log.recent(5);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].flow_id, 99);
    }
}
