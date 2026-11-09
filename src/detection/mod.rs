//! Detection scoring and event gating.
//!
//! A finding is security-relevant when it falls into `proxy`,
//! `proxy_transport`, or `obfuscation`. Direct proxy evidence can trigger
//! automatic blocking; transport and TLS-mimicry evidence is surfaced for
//! monitoring and must be matched by an explicit rule before it can block.

use crate::dpi::{Finding, FlowAnalysis, CAT_OBFUSCATION, CAT_PROXY, CAT_PROXY_TRANSPORT};

#[derive(Debug, Clone)]
pub struct Assessment {
    pub security_relevant: bool,
    pub should_emit: bool,
    pub strongest: Option<Finding>,
    pub security_confidence: f32,
    pub fingerprint: u64,
}

pub fn assess(
    analysis: &FlowAnalysis,
    detection_enabled: bool,
    monitor_threshold: f32,
) -> Assessment {
    let security: Vec<&Finding> = analysis
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.category.as_str(),
                CAT_PROXY | CAT_PROXY_TRANSPORT | CAT_OBFUSCATION
            )
        })
        .collect();
    let security_confidence = security.iter().map(|f| f.confidence).fold(0.0f32, f32::max);
    let strongest = security
        .iter()
        .max_by(|a, b| {
            a.confidence
                .partial_cmp(&b.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|f| (*f).clone());
    let should_emit =
        detection_enabled && !security.is_empty() && security_confidence >= monitor_threshold;
    Assessment {
        security_relevant: !security.is_empty(),
        should_emit,
        strongest,
        security_confidence,
        fingerprint: fingerprint(analysis),
    }
}

/// FNV-1a over sorted protocol names. Used to suppress duplicate events for
/// repeated analysis of the same flow.
pub fn fingerprint(analysis: &FlowAnalysis) -> u64 {
    let mut names = analysis.detected_protocols.clone();
    names.sort();
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut add = |value: &str| {
        for byte in value.as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    for name in names {
        add(&name);
    }
    if let Some(sni) = &analysis.sni {
        add(sni);
    }
    for name in &analysis.dns_names {
        add(name);
    }
    // Confidence upgrades are meaningful for monitoring (for example a SOCKS
    // greeting becomes a complete request). Round to avoid fingerprint churn.
    add(&format!("max:{:.2}", analysis.max_confidence));
    add(&format!("proxy:{:.2}", analysis.proxy_score));
    add(&format!("transport:{:.2}", analysis.proxy_transport_score));
    add(&format!("obfuscation:{:.2}", analysis.obfuscation_score));
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpi::Finding;

    fn analysis(findings: Vec<Finding>) -> FlowAnalysis {
        FlowAnalysis {
            findings,
            ..Default::default()
        }
    }

    #[test]
    fn tls_alone_is_not_security_relevant() {
        let a = analysis(vec![Finding {
            protocol: "tls".into(),
            category: "encrypted".into(),
            confidence: 0.99,
            evidence: vec![],
        }]);
        let assessment = assess(&a, true, 0.5);
        assert!(!assessment.should_emit);
    }

    #[test]
    fn proxy_emits_above_threshold() {
        let a = analysis(vec![Finding {
            protocol: "socks5".into(),
            category: "proxy".into(),
            confidence: 0.97,
            evidence: vec![],
        }]);
        let assessment = assess(&a, true, 0.5);
        assert!(assessment.should_emit);
        assert_eq!(assessment.strongest.unwrap().protocol, "socks5");
    }

    #[test]
    fn disabled_detection_suppresses_automatic_events() {
        let a = analysis(vec![Finding {
            protocol: "socks5".into(),
            category: "proxy".into(),
            confidence: 0.97,
            evidence: vec![],
        }]);
        let assessment = assess(&a, false, 0.5);
        assert!(!assessment.should_emit);
    }

    #[test]
    fn weak_heuristic_below_threshold_does_not_emit() {
        let a = analysis(vec![Finding {
            protocol: "reality-suspected".into(),
            category: "obfuscation".into(),
            confidence: 0.24,
            evidence: vec![],
        }]);
        let assessment = assess(&a, true, 0.5);
        assert!(!assessment.should_emit);
        assert!(assessment.security_relevant);
    }

    #[test]
    fn fingerprint_changes_with_protocols() {
        let a = analysis(vec![Finding {
            protocol: "tls".into(),
            category: "encrypted".into(),
            confidence: 0.9,
            evidence: vec![],
        }]);
        let mut b = a.clone();
        b.detected_protocols = vec!["tls".into(), "websocket".into()];
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }
}
