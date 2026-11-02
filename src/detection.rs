//! Conservative, explainable flow classification. These signals are not protocol signatures.
use crate::flow::Flow;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    NormalTls,
    SuspiciousEncryptedTunnel,
    SuspectedVlessReality,
    OtherEncryptedTraffic,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalDetection {
    pub classification: Classification,
    /// Heuristic score in [0,1], not a probability or measured accuracy.
    pub suspicion_score: f64,
    pub observations: Vec<String>,
    pub explanation: String,
    pub ai_requested: bool,
}

#[derive(Clone, Debug)]
pub struct HeuristicConfig {
    pub duration_weight: f64,
    pub bidirectional_weight: f64,
    pub volume_weight: f64,
    pub packets_weight: f64,
    pub threshold: f64,
}

impl Default for HeuristicConfig {
    fn default() -> Self {
        fn value(name: &str, default: f64) -> f64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
                .unwrap_or(default)
        }
        Self {
            duration_weight: value("AXION_WEIGHT_DURATION", 0.25),
            bidirectional_weight: value("AXION_WEIGHT_BIDIRECTIONAL", 0.20),
            volume_weight: value("AXION_WEIGHT_VOLUME", 0.25),
            packets_weight: value("AXION_WEIGHT_PACKETS", 0.20),
            threshold: value("AXION_SUSPICION_THRESHOLD", 0.70),
        }
    }
}

/// An interface suitable for replacing the heuristics with a local model.
pub trait FlowClassifier: Send + Sync {
    fn classify(&self, flow: &Flow) -> LocalDetection;
}

impl FlowClassifier for HeuristicConfig {
    fn classify(&self, flow: &Flow) -> LocalDetection {
        let mut score: f64 = 0.0;
        let mut observations = Vec::new();
        let packets = flow.packets_sent.saturating_add(flow.packets_received);
        let bytes = flow.bytes_sent.saturating_add(flow.bytes_received);
        let has_tls = flow.tls.is_some();
        if has_tls {
            observations.push("TLS ClientHello observed".to_string());
        }
        if flow.duration_ms() >= 60_000 {
            score += self.duration_weight;
            observations.push("Flow observed for at least 60 seconds".to_string());
        }
        if flow.bytes_sent >= 16_384 && flow.bytes_received >= 16_384 {
            score += self.bidirectional_weight;
            observations.push("At least 16 KiB observed in each direction".to_string());
        }
        if bytes >= 1_048_576 {
            score += self.volume_weight;
            observations.push("At least 1 MiB observed across both directions".to_string());
        }
        if packets >= 500 {
            score += self.packets_weight;
            observations.push("At least 500 packets observed".to_string());
        }
        score = score.clamp(0.0, 1.0);
        // These behaviours occur in benign applications, too. Require observed TLS and
        // several signals, and never infer REALITY identity from them.
        let suspicious = has_tls && observations.len() >= 4 && score >= self.threshold;
        let classification = if suspicious {
            Classification::SuspiciousEncryptedTunnel
        } else {
            Classification::Unknown
        };
        let explanation = if suspicious {
            "Sustained bidirectional TLS traffic warrants review; these behaviours also occur in ordinary applications and do not establish a tunnel or VLESS identity."
        } else {
            "Insufficient distinguishing evidence; ordinary TLS and encrypted tunnels can look alike."
        }.to_string();
        LocalDetection {
            classification,
            suspicion_score: score,
            observations,
            explanation,
            ai_requested: false,
        }
    }
}

pub fn classify(flow: &Flow) -> LocalDetection {
    HeuristicConfig::default().classify(flow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        flow::FlowTable,
        packet::{Packet, Protocol},
        tls::TlsInfo,
    };
    fn sample() -> Flow {
        let packet = Packet {
            timestamp_ms: 1,
            src: "192.0.2.1:40000".parse().unwrap(),
            dst: "198.51.100.1:443".parse().unwrap(),
            protocol: Protocol::Tcp,
            wire_len: 100,
            tcp_seq: Some(1),
            tcp_flags: 2,
            payload: vec![],
        };
        FlowTable::new(10, 1000).ingest(packet)
    }
    #[test]
    fn no_port_or_fingerprint_conclusions() {
        let mut flow = sample();
        flow.tls = Some(TlsInfo {
            ja3: Some("known-value".into()),
            ..Default::default()
        });
        let result = classify(&flow);
        assert_eq!(result.classification, Classification::Unknown);
        assert!(!result.ai_requested);
    }
    #[test]
    fn sustained_behavior_is_suspicion_not_vless_identity() {
        let mut flow = sample();
        flow.tls = Some(TlsInfo::default());
        flow.last_seen_ms = 90_001;
        flow.packets_sent = 500;
        flow.packets_received = 500;
        flow.bytes_sent = 1_000_000;
        flow.bytes_received = 1_000_000;
        let result = classify(&flow);
        assert_eq!(
            result.classification,
            Classification::SuspiciousEncryptedTunnel
        );
        assert!(result.explanation.contains("do not establish"));
    }
}
