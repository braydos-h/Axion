//! Configuration schema, defaults, loading and validation.
//!
//! The on-disk format is TOML. Unknown fields are rejected so operators get
//! immediate feedback for typos instead of silently running with defaults.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/axion/axion.toml";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Passive observation. Never alters traffic (except returning ACCEPT on
    /// an inline NFQUEUE backend).
    Monitor,
    /// Inline enforcement. Requires the NFQUEUE backend.
    Enforce,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Monitor => f.write_str("monitor"),
            Mode::Enforce => f.write_str("enforce"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Drop,
    Reject,
    Log,
    Monitor,
}

impl Action {
    pub fn is_blocking(self) -> bool {
        matches!(self, Action::Drop | Action::Reject)
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Allow => f.write_str("allow"),
            Action::Drop => f.write_str("drop"),
            Action::Reject => f.write_str("reject"),
            Action::Log => f.write_str("log"),
            Action::Monitor => f.write_str("monitor"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub general: GeneralConfig,
    pub capture: CaptureConfig,
    pub api: ApiConfig,
    pub telemetry: TelemetryConfig,
    pub firewall: FirewallConfig,
    pub detection: DetectionConfig,
    pub policy: PolicyConfig,
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GeneralConfig {
    pub mode: Mode,
    pub dry_run: bool,
    /// Zero means "one worker per available CPU, capped at 8".
    pub worker_threads: usize,
    pub max_flows: usize,
    pub flow_idle_timeout_seconds: u64,
    pub fragment_timeout_seconds: u64,
    pub max_fragment_sets: usize,
    pub max_fragment_bytes: usize,
    pub max_reassembly_bytes: usize,
    pub event_capacity: usize,
    pub auto_block_confidence: f32,
    pub monitor_confidence: f32,
    pub log_level: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Monitor,
            dry_run: false,
            worker_threads: 0,
            max_flows: 100_000,
            flow_idle_timeout_seconds: 120,
            fragment_timeout_seconds: 30,
            max_fragment_sets: 4096,
            max_fragment_bytes: 16 * 1024 * 1024,
            max_reassembly_bytes: 256 * 1024,
            event_capacity: 4096,
            auto_block_confidence: 0.92,
            monitor_confidence: 0.50,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureBackend {
    /// Probe for a usable backend: AF_PACKET first, then libpcap.
    Auto,
    /// Native Linux AF_PACKET socket (no libpcap dependency).
    AfPacket,
    /// Dynamically loaded libpcap (pcap_open_live). Requires libpcap.so at runtime.
    Libpcap,
    /// Do not capture. Useful for API-only deployments and some tests.
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    pub backend: CaptureBackend,
    pub interface: String,
    /// When set, `start` replays this capture instead of opening a live source.
    pub pcap_file: Option<PathBuf>,
    pub snaplen: usize,
    pub buffer_bytes: usize,
    pub batch_size: usize,
    /// Bounded capture-to-worker queue. Full queues drop frames and increment
    /// the capture_drops counter rather than growing memory.
    pub queue_capacity: usize,
    pub promiscuous: bool,
    /// AF_PACKET also delivers locally originated frames. Keep this enabled
    /// when monitoring egress; the kernel reports them as PACKET_OUTGOING.
    pub include_outgoing: bool,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            backend: CaptureBackend::Auto,
            interface: "eth0".to_string(),
            pcap_file: None,
            snaplen: 2048,
            buffer_bytes: 8 * 1024 * 1024,
            batch_size: 64,
            queue_capacity: 2048,
            promiscuous: true,
            include_outgoing: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub enabled: bool,
    pub bind: SocketAddr,
    /// Optional bearer token. If unset and `bind` is not loopback, Axion
    /// refuses to start unless `allow_insecure_remote` is true.
    pub token: Option<String>,
    pub allow_insecure_remote: bool,
    pub request_body_limit: usize,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:8787"
                .parse()
                .expect("valid default socket address"),
            token: None,
            allow_insecure_remote: false,
            request_body_limit: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    pub sample_interval_ms: u64,
    pub history_seconds: usize,
    pub log_detections: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            sample_interval_ms: 1000,
            history_seconds: 120,
            log_detections: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub queue_num: u16,
    pub queue_max_len: u32,
    /// Packets processed per NFQUEUE receive iteration. Verdicts are batched.
    pub batch_size: usize,
    /// If userspace dies or the queue is full, accept packets instead of
    /// black-holing them. This is also mirrored to NFQA_CFG_F_FAIL_OPEN.
    pub fail_open: bool,
    /// Management/services that must never be blocked by Axion.
    pub bypass_tcp_ports: Vec<u16>,
    pub bypass_cidrs: Vec<String>,
    /// NFQUEUE supports ACCEPT and DROP. REJECT rules are enforced as DROP;
    /// operators may use a firewall reject rule for ICMP/TCP reset semantics.
    pub reject_emulation: String,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            queue_num: 0,
            queue_max_len: 1024,
            batch_size: 64,
            fail_open: true,
            bypass_tcp_ports: vec![22, 8787],
            bypass_cidrs: vec!["127.0.0.0/8".to_string(), "::1/128".to_string()],
            reject_emulation: "drop".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DetectionConfig {
    /// Enables automatic monitoring events and built-in proxy auto-blocking.
    /// Explicit rules still evaluate when this is false.
    pub enabled: bool,
    pub enable_quic_initial: bool,
    pub enable_tls_fingerprint: bool,
    /// Enables low-confidence behavioural detectors (TLS mimicry, opaque
    /// stream scoring). These never auto-block on their own.
    pub enable_heuristics: bool,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_quic_initial: true,
            enable_tls_fingerprint: true,
            enable_heuristics: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub default_action: Action,
    /// Evaluate ALLOW rules before all other rules, regardless of numeric
    /// priority. This makes allowlists a hard override by default.
    pub allow_overrides: bool,
    pub allowlist_cidrs: Vec<String>,
    pub blocklist_cidrs: Vec<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: Action::Allow,
            allow_overrides: true,
            allowlist_cidrs: Vec::new(),
            blocklist_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleConfig {
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub priority: i32,
    pub action: Action,
    pub log: bool,
    #[serde(rename = "match")]
    pub matcher: MatchConfig,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            name: "unnamed".to_string(),
            description: None,
            enabled: true,
            priority: 100,
            action: Action::Monitor,
            log: false,
            matcher: MatchConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectionMatch {
    #[default]
    Either,
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MatchConfig {
    pub src_cidrs: Vec<String>,
    pub dst_cidrs: Vec<String>,
    /// Matches either the source or destination port unless direction is set.
    pub ports: Vec<u16>,
    pub src_ports: Vec<u16>,
    pub transports: Vec<String>,
    /// Classifier labels such as `tls`, `http`, `socks5`, `xray-vless`.
    pub protocols: Vec<String>,
    /// Classifier categories such as `proxy`, `proxy_transport`,
    /// `encrypted`, `dns`, `http`.
    pub categories: Vec<String>,
    /// Glob patterns (`*` and `?`) matched case-insensitively against SNI.
    pub sni: Vec<String>,
    /// Glob patterns matched case-insensitively against observed DNS names.
    pub dns: Vec<String>,
    pub direction: DirectionMatch,
    pub min_confidence: f32,
    pub max_confidence: Option<f32>,
    pub min_bytes: Option<u64>,
    pub min_duration_ms: Option<u64>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        cfg.apply_env();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load_optional(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let mut cfg = Self::default();
            cfg.apply_env();
            cfg.validate()?;
            Ok(cfg)
        }
    }

    fn apply_env(&mut self) {
        if let Ok(token) = std::env::var("AXION_API_TOKEN") {
            if !token.is_empty() {
                self.api.token = Some(token);
            }
        }
        if let Ok(bind) = std::env::var("AXION_API_BIND") {
            if let Ok(addr) = bind.parse() {
                self.api.bind = addr;
            }
        }
        if let Ok(iface) = std::env::var("AXION_INTERFACE") {
            if !iface.is_empty() {
                self.capture.interface = iface;
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();
        if !(0.0..=1.0).contains(&self.general.auto_block_confidence) {
            errors.push("general.auto_block_confidence must be in [0, 1]".to_string());
        }
        if !(0.0..=1.0).contains(&self.general.monitor_confidence) {
            errors.push("general.monitor_confidence must be in [0, 1]".to_string());
        }
        if self.general.max_flows < 16 {
            errors.push("general.max_flows must be at least 16".to_string());
        }
        if self.general.worker_threads > 256 {
            errors.push("general.worker_threads must be <= 256".to_string());
        }
        if !(1024..=16 * 1024 * 1024).contains(&self.general.max_reassembly_bytes) {
            errors.push("general.max_reassembly_bytes must be in [1024, 16777216]".to_string());
        }
        if self.general.max_fragment_bytes < 65535 {
            errors.push("general.max_fragment_bytes must be at least 65535".to_string());
        }
        if self.general.max_fragment_sets < 1 {
            errors.push("general.max_fragment_sets must be at least 1".to_string());
        }
        if self.general.event_capacity < 16 {
            errors.push("general.event_capacity must be at least 16".to_string());
        }
        if self.capture.snaplen < 64 || self.capture.snaplen > 65535 {
            errors.push("capture.snaplen must be in [64, 65535]".to_string());
        }
        if self.capture.batch_size == 0 || self.capture.batch_size > 1024 {
            errors.push("capture.batch_size must be in [1, 1024]".to_string());
        }
        if self.capture.queue_capacity < 64 || self.capture.queue_capacity > 1_000_000 {
            errors.push("capture.queue_capacity must be in [64, 1000000]".to_string());
        }
        if self.api.bind.port() == 0 {
            errors.push("api.bind port must not be 0".to_string());
        }
        if self.api.token.as_deref().is_some_and(str::is_empty) {
            errors.push("api.token must not be empty when set".to_string());
        }
        if !self.api.bind.ip().is_loopback()
            && self.api.token.as_deref().unwrap_or("").is_empty()
            && !self.api.allow_insecure_remote
        {
            errors.push(
                "api.bind is not loopback and api.token is empty; set a token or \
                 api.allow_insecure_remote = true explicitly"
                    .to_string(),
            );
        }
        if self.api.request_body_limit < 1024 {
            errors.push("api.request_body_limit must be at least 1024".to_string());
        }
        if self.general.mode == Mode::Enforce && self.capture.pcap_file.is_some() {
            errors.push("enforce mode cannot replay a pcap file".to_string());
        }
        if self.firewall.reject_emulation != "drop" {
            errors.push("firewall.reject_emulation currently only supports \"drop\"".to_string());
        }
        if self.firewall.batch_size == 0 || self.firewall.batch_size > 1024 {
            errors.push("firewall.batch_size must be in [1, 1024]".to_string());
        }
        for cidr in self
            .policy
            .allowlist_cidrs
            .iter()
            .chain(self.policy.blocklist_cidrs.iter())
            .chain(self.firewall.bypass_cidrs.iter())
        {
            if let Err(err) = cidr.parse::<ipnet::IpNet>() {
                errors.push(format!("invalid CIDR {cidr:?}: {err}"));
            }
        }
        let mut names = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.name.trim().is_empty() {
                errors.push("rule name must not be empty".to_string());
            }
            if !names.insert(rule.name.clone()) {
                errors.push(format!("duplicate rule name {:?}", rule.name));
            }
            if !(0.0..=1.0).contains(&rule.matcher.min_confidence) {
                errors.push(format!(
                    "rule {:?}: min_confidence must be in [0, 1]",
                    rule.name
                ));
            }
            if let Some(max) = rule.matcher.max_confidence {
                if !(0.0..=1.0).contains(&max) || max < rule.matcher.min_confidence {
                    errors.push(format!(
                        "rule {:?}: max_confidence must be in [min_confidence, 1]",
                        rule.name
                    ));
                }
            }
            for cidr in rule
                .matcher
                .src_cidrs
                .iter()
                .chain(rule.matcher.dst_cidrs.iter())
            {
                if let Err(err) = cidr.parse::<ipnet::IpNet>() {
                    errors.push(format!(
                        "rule {:?}: invalid CIDR {cidr:?}: {err}",
                        rule.name
                    ));
                }
            }
            for transport in &rule.matcher.transports {
                if !matches!(transport.as_str(), "tcp" | "udp" | "icmp" | "icmpv6") {
                    errors.push(format!(
                        "rule {:?}: unsupported transport {transport:?}",
                        rule.name
                    ));
                }
            }
        }
        if !errors.is_empty() {
            anyhow::bail!("configuration is invalid:\n  - {}", errors.join("\n  - "));
        }
        Ok(())
    }

    pub fn effective_worker_threads(&self) -> usize {
        if self.general.worker_threads > 0 {
            self.general.worker_threads
        } else {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .clamp(1, 8)
        }
    }
}

/// Default sample configuration written to `config/axion.toml` and embedded in
/// the binary for `axion config example`.
pub const EXAMPLE_CONFIG: &str = include_str!("../../config/axion.example.toml");

#[cfg(test)]
mod tests {
    #![allow(clippy::field_reassign_with_default)]
    use super::*;

    #[test]
    fn defaults_validate() {
        Config::default().validate().expect("defaults are valid");
    }

    #[test]
    fn remote_api_requires_token() {
        let mut cfg = Config::default();
        cfg.api.bind = "0.0.0.0:8787".parse().unwrap();
        assert!(cfg.validate().is_err());
        cfg.api.token = Some("secret".into());
        cfg.validate().unwrap();
    }

    #[test]
    fn duplicate_rules_rejected() {
        let mut cfg = Config::default();
        cfg.rules = vec![
            RuleConfig {
                name: "same".into(),
                ..Default::default()
            },
            RuleConfig {
                name: "same".into(),
                ..Default::default()
            },
        ];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate rule"));
    }

    #[test]
    fn parse_minimal_toml() {
        let cfg: Config = toml::from_str(
            r#"
            [general]
            mode = "monitor"
            [capture]
            interface = "lo"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.capture.interface, "lo");
    }

    #[test]
    fn reject_unknown_fields() {
        let result: Result<Config, _> = toml::from_str("[general]\nnot_a_real_key = 1\n");
        assert!(result.is_err());
    }
}
