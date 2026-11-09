//! Deterministic, isolated live demonstrations.
//!
//! A demo session owns a private [`Engine`] and replays embedded pcap fixtures
//! through the same packet parser, flow tracker, DPI classifier and rule engine
//! used by live capture. Nothing here opens a capture socket, touches firewall
//! state, writes a file from a request, or accepts an operator-supplied path.
//!
//! Sessions are bounded by [`DemoManager::max_sessions`], frames per scenario,
//! telemetry history and event capacity. The manager's ticker advances all
//! sessions; completed sessions expire after an inactivity TTL.

use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio::task::JoinHandle;

use crate::config::{Action, Config, MatchConfig, Mode, RuleConfig};
use crate::engine::Engine;
use crate::flow::{unix_ms, FlowSnapshot};
use crate::packet::{LinkType, PcapReader};
use crate::rules::RuleStore;
use crate::telemetry::{DetectionEvent, MetricsSnapshot, Telemetry};

/// Hard upper bound on concurrent demo sessions per server.
pub const MAX_DEMO_SESSIONS: usize = 8;
pub const SESSION_TTL_MS: u64 = 30 * 60 * 1000;
pub const MIN_SPEED: f64 = 0.25;
pub const MAX_SPEED: f64 = 8.0;
const MAX_FRAMES: usize = 2048;
const MAX_STEPS_PER_TICK: usize = 32;
const TICK_MS: u64 = 50;
const INITIAL_DELAY_MS: u64 = 350;
const COMPLETION_HOLD_MS: u64 = 1_200;
const SAMPLE_INTERVAL_MS: u64 = 250;

#[derive(Debug, Clone)]
pub enum DemoError {
    UnknownScenario(String),
    TooManySessions(usize),
    NotFound(String),
    InvalidSpeed(f64),
    InvalidState(&'static str),
    Internal(String),
}

impl fmt::Display for DemoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownScenario(id) => write!(f, "unknown demo scenario {id:?}"),
            Self::TooManySessions(max) => write!(
                f,
                "demo session limit reached ({max}); stop an existing session and retry"
            ),
            Self::NotFound(id) => write!(f, "demo session {id:?} was not found"),
            Self::InvalidSpeed(speed) => write!(
                f,
                "playback speed {speed} is outside the supported range {MIN_SPEED}-{MAX_SPEED}"
            ),
            Self::InvalidState(message) => write!(f, "{message}"),
            Self::Internal(message) => write!(f, "demo playback failed: {message}"),
        }
    }
}

impl std::error::Error for DemoError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybackState {
    Playing,
    Paused,
    Completed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleProfile {
    Default,
    Inspection,
    Enforcement,
    Mixed,
}

#[derive(Debug, Clone, Copy)]
struct Fixture {
    name: &'static str,
    data: &'static [u8],
}

const BENIGN_TLS: Fixture = Fixture {
    name: "benign_tls.pcap",
    data: include_bytes!("../../tests/fixtures/benign_tls.pcap"),
};
const BENIGN_TLS_NG: Fixture = Fixture {
    name: "benign_tls.pcapng",
    data: include_bytes!("../../tests/fixtures/benign_tls.pcapng"),
};
const BENIGN_HTTP: Fixture = Fixture {
    name: "benign_http.pcap",
    data: include_bytes!("../../tests/fixtures/benign_http.pcap"),
};
const BENIGN_DNS: Fixture = Fixture {
    name: "benign_dns.pcap",
    data: include_bytes!("../../tests/fixtures/benign_dns.pcap"),
};
const FRAGMENTED_DNS: Fixture = Fixture {
    name: "ipv4_fragmented_dns.pcap",
    data: include_bytes!("../../tests/fixtures/ipv4_fragmented_dns.pcap"),
};
const SOCKS5: Fixture = Fixture {
    name: "proxy_socks5.pcap",
    data: include_bytes!("../../tests/fixtures/proxy_socks5.pcap"),
};
const HTTP_CONNECT: Fixture = Fixture {
    name: "proxy_http_connect.pcap",
    data: include_bytes!("../../tests/fixtures/proxy_http_connect.pcap"),
};
const VLESS: Fixture = Fixture {
    name: "proxy_vless_plaintext.pcap",
    data: include_bytes!("../../tests/fixtures/proxy_vless_plaintext.pcap"),
};
const TROJAN: Fixture = Fixture {
    name: "proxy_trojan_plaintext.pcap",
    data: include_bytes!("../../tests/fixtures/proxy_trojan_plaintext.pcap"),
};

const FIXTURES: &[Fixture] = &[
    BENIGN_TLS,
    BENIGN_TLS_NG,
    BENIGN_HTTP,
    BENIGN_DNS,
    FRAGMENTED_DNS,
    SOCKS5,
    HTTP_CONNECT,
    VLESS,
    TROJAN,
];

#[derive(Debug, Serialize)]
pub struct DemoScenario {
    pub id: &'static str,
    pub number: u8,
    pub title: &'static str,
    pub tagline: &'static str,
    pub description: &'static str,
    pub fixtures: &'static [&'static str],
    pub focus: &'static [&'static str],
    pub expected: &'static [&'static str],
    pub caveats: &'static [&'static str],
    pub base_step_ms: u64,
    pub enforcement_demo: bool,
    #[serde(skip_serializing)]
    rule_profile: RuleProfile,
    #[serde(skip_serializing)]
    interleave: bool,
}

pub static SCENARIOS: &[DemoScenario] = &[
    DemoScenario {
        id: "normal-https",
        number: 1,
        title: "Normal HTTPS Traffic",
        tagline: "A TLS ClientHello is ordinary traffic, not a proxy verdict",
        description: "Replays a deterministic Chrome-like TLS 1.3 ClientHello from a pcapng \
                      capture. Axion parses the handshake boundary, SNI, ALPN, offered ciphers, \
                      extensions and a JA3-style fingerprint. The encrypted application data is \
                      never decrypted and TLS alone is not treated as malicious, so the default \
                      policy allows the flow.",
        fixtures: &["benign_tls.pcapng"],
        focus: &[
            "TLS record and ClientHello parsing",
            "SNI, ALPN, supported versions and fingerprint",
            "Why encrypted benign traffic is not auto-blocked",
        ],
        expected: &[
            "SNI www.example.com",
            "ALPN h2 / http/1.1",
            "Action allow, proxy score 0",
            "Weak REALITY-style metadata stays below the monitor threshold",
        ],
        caveats: &[
            "The TLS application payload is encrypted and is not inspected.",
            "Weak TLS mimicry findings are indicators, never proof of a proxy.",
        ],
        base_step_ms: 900,
        enforcement_demo: false,
        rule_profile: RuleProfile::Default,
        interleave: false,
    },
    DemoScenario {
        id: "socks5-proxy",
        number: 2,
        title: "SOCKS5 Proxy Detection",
        tagline: "A complete plaintext SOCKS5 connect request is direct evidence",
        description: "Replays a SOCKS5 greeting followed by a complete CONNECT request for \
                      example.com:443. The parser recognizes the version, stage, target address \
                      and port. A complete request scores 0.97 in the proxy category and crosses \
                      the built-in auto-block threshold, producing a real rule decision.",
        fixtures: &["proxy_socks5.pcap"],
        focus: &[
            "SOCKS5 greeting and request recognition",
            "Extracted target address and port",
            "Proxy confidence plus matched rule",
        ],
        expected: &[
            "socks5 finding at 0.97 proxy confidence",
            "Target example.com:443 extracted",
            "Rule action drop in monitor mode",
        ],
        caveats: &[
            "The demo runs in passive monitor mode; the drop decision is simulated.",
            "SOCKS5 can be legitimate software and may be explicitly allowlisted in production.",
        ],
        base_step_ms: 900,
        enforcement_demo: false,
        rule_profile: RuleProfile::Default,
        interleave: false,
    },
    DemoScenario {
        id: "http-connect",
        number: 3,
        title: "HTTP CONNECT Detection",
        tagline: "A CONNECT request exposes a proxy tunnel handshake",
        description: "Replays an HTTP CONNECT request targeting example.com:443. Axion parses \
                      the request line and headers, records the host, and classifies the CONNECT \
                      tunnel as direct proxy evidence. The body inside a real tunnel would remain \
                      encrypted.",
        fixtures: &["proxy_http_connect.pcap"],
        focus: &[
            "HTTP/1.x request and header parsing",
            "CONNECT method and tunnel target",
            "Proxy finding and policy decision",
        ],
        expected: &[
            "http-connect finding at 0.97 proxy confidence",
            "Host and CONNECT target example.com:443",
            "Rule action drop in monitor mode",
        ],
        caveats: &[
            "Only the CONNECT header block is observable.",
            "Content inside the tunnel is not decrypted by Axion.",
        ],
        base_step_ms: 900,
        enforcement_demo: false,
        rule_profile: RuleProfile::Default,
        interleave: false,
    },
    DemoScenario {
        id: "vless-trojan",
        number: 4,
        title: "VLESS and Trojan Detection",
        tagline: "Plaintext fallback headers are parsed field by field",
        description: "Replays the plaintext VLESS and Trojan fixtures. Axion validates the VLESS \
                      version, UUID, command and target, and the Trojan password-hash/command \
                      layout. Both are direct proxy findings. This does not decrypt normal \
                      TLS-wrapped VLESS or Trojan sessions.",
        fixtures: &["proxy_vless_plaintext.pcap", "proxy_trojan_plaintext.pcap"],
        focus: &[
            "Field-validated VLESS request parsing",
            "Field-validated plaintext Trojan parsing",
            "Honest limits for encrypted proxy transports",
        ],
        expected: &[
            "xray-vless finding around 0.95",
            "trojan-plaintext finding at 0.97",
            "Two real proxy detections and drop decisions",
        ],
        caveats: &[
            "TLS-wrapped VLESS and Trojan are not decryptable without keys.",
            "These results only apply to visible plaintext headers.",
        ],
        base_step_ms: 900,
        enforcement_demo: false,
        rule_profile: RuleProfile::Default,
        interleave: false,
    },
    DemoScenario {
        id: "dns-http",
        number: 5,
        title: "DNS and HTTP Inspection",
        tagline: "Real names, hosts, methods and query types from cleartext protocols",
        description: "Replays a DNS query and an HTTP GET. Axion extracts the queried name and \
                      record type, plus the HTTP method, host, target and version. Demo-only \
                      visibility rules turn these classifications into monitor events so the \
                      event stream can be inspected without implying the traffic is malicious.",
        fixtures: &["benign_dns.pcap", "benign_http.pcap"],
        focus: &[
            "DNS question name and query type",
            "HTTP request metadata",
            "Monitor/log policy visibility without enforcement",
        ],
        expected: &[
            "DNS query www.example.com A at 0.97",
            "HTTP GET / for example.com at 0.97",
            "Monitor events from explicit demo rules",
        ],
        caveats: &[
            "DoH and DoT hide DNS names inside encrypted HTTP/TLS.",
            "Monitor and log actions never drop traffic.",
        ],
        base_step_ms: 900,
        enforcement_demo: false,
        rule_profile: RuleProfile::Inspection,
        interleave: false,
    },
    DemoScenario {
        id: "traffic-enforcement",
        number: 6,
        title: "Traffic Enforcement",
        tagline: "Allow, monitor, log and drop decisions without touching the host firewall",
        description: "Replays benign TLS, DNS, HTTP and two plaintext proxy handshakes through a \
                      small demo policy. The real rule engine selects an explicit allow, monitor, \
                      log or drop decision. Playback is permanently in passive monitor mode, so \
                      drop verdicts are displayed as simulated and no packet is ever discarded.",
        fixtures: &[
            "benign_tls.pcap",
            "benign_dns.pcap",
            "benign_http.pcap",
            "proxy_socks5.pcap",
            "proxy_http_connect.pcap",
        ],
        focus: &[
            "Explicit ALLOW and priority ordering",
            "Monitor/log events for visibility",
            "DROP verdicts with no real enforcement",
        ],
        expected: &[
            "allow-trusted-https matches the TLS flow",
            "monitor-dns-queries and log-http-requests fire",
            "drop-plaintext-proxies matches both proxy fixture flows",
        ],
        caveats: &[
            "Passive capture can classify and decide but cannot drop packets.",
            "A real deployment only enforces through the NFQUEUE inline backend.",
            "This demo never installs firewall rules or opens NFQUEUE.",
        ],
        base_step_ms: 800,
        enforcement_demo: true,
        rule_profile: RuleProfile::Enforcement,
        interleave: false,
    },
    DemoScenario {
        id: "mixed-traffic",
        number: 7,
        title: "Mixed Traffic Simulation",
        tagline: "All fixture families interleaved over a live-updating timeline",
        description: "Round-robins all labelled fixture families, including the out-of-order \
                      IPv4-fragmented DNS capture. Charts, protocol distribution, flows, events \
                      and rule decisions update as the real pipeline processes each frame.",
        fixtures: &[
            "benign_tls.pcap",
            "benign_dns.pcap",
            "benign_http.pcap",
            "proxy_socks5.pcap",
            "proxy_http_connect.pcap",
            "proxy_vless_plaintext.pcap",
            "proxy_trojan_plaintext.pcap",
            "ipv4_fragmented_dns.pcap",
        ],
        focus: &[
            "Interleaved deterministic fixture timeline",
            "Live rate, flow, protocol and event updates",
            "Mixed benign and proxy verdicts in one policy",
        ],
        expected: &[
            "Eight fixture families replayed in a stable order",
            "DNS/HTTP visibility events plus proxy drop decisions",
            "Out-of-order IP fragments reassembled before DNS parsing",
        ],
        caveats: &[
            "The mixed timeline is a synthetic replay, not sampled Internet traffic.",
            "Rates reflect playback pacing, not production throughput.",
        ],
        base_step_ms: 650,
        enforcement_demo: true,
        rule_profile: RuleProfile::Mixed,
        interleave: true,
    },
];

pub fn scenarios() -> &'static [DemoScenario] {
    SCENARIOS
}

pub fn scenario(id: &str) -> Option<&'static DemoScenario> {
    SCENARIOS.iter().find(|scenario| scenario.id == id)
}

fn fixture(name: &str) -> Option<&'static Fixture> {
    FIXTURES.iter().find(|fixture| fixture.name == name)
}

fn rule(
    name: &'static str,
    priority: i32,
    action: Action,
    matcher: MatchConfig,
    log: bool,
) -> RuleConfig {
    RuleConfig {
        name: name.to_string(),
        description: Some("Demo-only policy rule".to_string()),
        enabled: true,
        priority,
        action,
        log,
        matcher,
    }
}

fn matcher() -> MatchConfig {
    MatchConfig::default()
}

fn rules_for(profile: RuleProfile) -> Vec<RuleConfig> {
    match profile {
        RuleProfile::Default => Vec::new(),
        RuleProfile::Inspection => vec![
            rule(
                "demo-monitor-dns",
                100,
                Action::Monitor,
                MatchConfig {
                    categories: vec!["dns".into()],
                    ..matcher()
                },
                true,
            ),
            rule(
                "demo-monitor-http",
                90,
                Action::Monitor,
                MatchConfig {
                    protocols: vec!["http1".into()],
                    ..matcher()
                },
                true,
            ),
        ],
        RuleProfile::Enforcement => vec![
            rule(
                "allow-trusted-https",
                300,
                Action::Allow,
                MatchConfig {
                    sni: vec!["www.example.com".into()],
                    ..matcher()
                },
                true,
            ),
            rule(
                "monitor-dns-queries",
                80,
                Action::Monitor,
                MatchConfig {
                    categories: vec!["dns".into()],
                    ..matcher()
                },
                true,
            ),
            rule(
                "log-http-requests",
                60,
                Action::Log,
                MatchConfig {
                    ports: vec![80],
                    protocols: vec!["http1".into()],
                    ..matcher()
                },
                true,
            ),
            rule(
                "drop-plaintext-proxies",
                100,
                Action::Drop,
                MatchConfig {
                    categories: vec!["proxy".into()],
                    ..matcher()
                },
                true,
            ),
        ],
        RuleProfile::Mixed => vec![
            rule(
                "mixed-monitor-dns",
                70,
                Action::Monitor,
                MatchConfig {
                    categories: vec!["dns".into()],
                    ..matcher()
                },
                true,
            ),
            rule(
                "mixed-log-http",
                60,
                Action::Log,
                MatchConfig {
                    ports: vec![80],
                    protocols: vec!["http1".into()],
                    ..matcher()
                },
                true,
            ),
            rule(
                "mixed-drop-proxies",
                100,
                Action::Drop,
                MatchConfig {
                    categories: vec!["proxy".into()],
                    ..matcher()
                },
                true,
            ),
        ],
    }
}

fn demo_config(profile: RuleProfile) -> Config {
    let mut config = Config::default();
    config.general.mode = Mode::Monitor;
    config.general.dry_run = true;
    config.general.worker_threads = 1;
    config.general.max_flows = 512;
    config.general.flow_idle_timeout_seconds = 300;
    config.general.event_capacity = 512;
    config.capture.backend = crate::config::CaptureBackend::None;
    config.capture.pcap_file = None;
    config.api.enabled = false;
    config.telemetry.log_detections = false;
    config.telemetry.sample_interval_ms = SAMPLE_INTERVAL_MS;
    config.telemetry.history_seconds = 60;
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    config.rules = rules_for(profile);
    config
}

fn create_engine(scenario: &DemoScenario) -> Result<Arc<Engine>, DemoError> {
    let config = demo_config(scenario.rule_profile);
    config
        .validate()
        .map_err(|err| DemoError::Internal(format!("invalid built-in demo config: {err:#}")))?;
    let config = Arc::new(config);
    let telemetry = Arc::new(Telemetry::new(
        config.telemetry.history_seconds,
        config.telemetry.sample_interval_ms,
        config.general.event_capacity,
    ));
    let rules = RuleStore::new(PathBuf::from("<embedded-demo>"), &config)
        .map_err(|err| DemoError::Internal(format!("compile demo rules: {err:#}")))?;
    Engine::new(Arc::clone(&config), rules, telemetry, false, "demo-replay")
        .map_err(|err| DemoError::Internal(format!("start demo engine: {err:#}")))
}

#[derive(Debug, Clone)]
struct DemoFrame {
    data: Vec<u8>,
    timestamp: Option<SystemTime>,
    link_type: LinkType,
}

fn load_frames(scenario: &DemoScenario) -> Result<Vec<DemoFrame>, DemoError> {
    let mut streams: Vec<Vec<DemoFrame>> = Vec::with_capacity(scenario.fixtures.len());
    for name in scenario.fixtures {
        let fixture = fixture(name)
            .ok_or_else(|| DemoError::Internal(format!("fixture {name:?} is not embedded")))?;
        let mut reader = PcapReader::new(Cursor::new(fixture.data))
            .map_err(|err| DemoError::Internal(format!("open fixture {name}: {err}")))?;
        let mut frames = Vec::new();
        while let Some(record) = reader
            .next_record()
            .map_err(|err| DemoError::Internal(format!("read fixture {name}: {err}")))?
        {
            if frames.len() + 1 > MAX_FRAMES {
                return Err(DemoError::Internal(format!(
                    "fixture {name} exceeds the demo frame bound"
                )));
            }
            frames.push(DemoFrame {
                data: record.data,
                timestamp: record.timestamp,
                link_type: record.link_type,
            });
        }
        if frames.is_empty() {
            return Err(DemoError::Internal(format!(
                "fixture {name} contains no packets"
            )));
        }
        streams.push(frames);
    }

    let mut frames = Vec::new();
    if scenario.interleave {
        let longest = streams.iter().map(Vec::len).max().unwrap_or(0);
        for index in 0..longest {
            for stream in &streams {
                if let Some(frame) = stream.get(index) {
                    if frames.len() >= MAX_FRAMES {
                        return Err(DemoError::Internal(
                            "demo scenario exceeds the global frame bound".to_string(),
                        ));
                    }
                    frames.push(frame.clone());
                }
            }
        }
    } else {
        for stream in streams {
            for frame in stream {
                if frames.len() >= MAX_FRAMES {
                    return Err(DemoError::Internal(
                        "demo scenario exceeds the global frame bound".to_string(),
                    ));
                }
                frames.push(frame);
            }
        }
    }
    if frames.is_empty() {
        return Err(DemoError::Internal(
            "demo scenario has no replayable frames".to_string(),
        ));
    }
    Ok(frames)
}

fn validate_speed(speed: f64) -> Result<f64, DemoError> {
    if !speed.is_finite() || !(MIN_SPEED..=MAX_SPEED).contains(&speed) {
        return Err(DemoError::InvalidSpeed(speed));
    }
    Ok(speed)
}

struct DemoRuntime {
    engine: Arc<Engine>,
    frames: Vec<DemoFrame>,
    cursor: usize,
    state: PlaybackState,
    speed: f64,
    created_ms: u64,
    updated_ms: u64,
    next_due_ms: u64,
    hold_until_ms: Option<u64>,
    last_sample_ms: u64,
}

impl DemoRuntime {
    fn new(scenario: &DemoScenario, speed: f64, now_ms: u64) -> Result<Self, DemoError> {
        Ok(Self {
            engine: create_engine(scenario)?,
            frames: load_frames(scenario)?,
            cursor: 0,
            state: PlaybackState::Playing,
            speed,
            created_ms: now_ms,
            updated_ms: now_ms,
            next_due_ms: now_ms.saturating_add(INITIAL_DELAY_MS),
            hold_until_ms: None,
            last_sample_ms: 0,
        })
    }
}

pub struct DemoSession {
    id: String,
    scenario: &'static DemoScenario,
    runtime: Mutex<DemoRuntime>,
    last_access_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DemoSessionSummary {
    pub id: String,
    pub scenario_id: &'static str,
    pub scenario_title: &'static str,
    pub state: PlaybackState,
    pub speed: f64,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub progress: f32,
    pub processed_frames: usize,
    pub total_frames: usize,
    pub packets: u64,
    pub bytes: u64,
    pub active_flows: u64,
    pub detections: u64,
    pub simulated_drops: u64,
}

#[derive(Debug, Serialize)]
pub struct DemoEnforcementInfo {
    pub mode: String,
    pub can_enforce: bool,
    pub enforcement_active: bool,
    pub simulated: bool,
    pub note: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DemoIsolation {
    pub fixture_replay: bool,
    pub real_capture: bool,
    pub real_enforcement: bool,
    pub external_network: bool,
    pub accepts_paths: bool,
    pub accepts_uploads: bool,
    pub note: &'static str,
}

pub static ISOLATION: DemoIsolation = DemoIsolation {
    fixture_replay: true,
    real_capture: false,
    real_enforcement: false,
    external_network: false,
    accepts_paths: false,
    accepts_uploads: false,
    note:
        "Embedded fixtures are replayed into a private monitor-only engine. No capture socket, \
           firewall rule, NFQUEUE handle, filesystem path, upload or external network call is used.",
};

#[derive(Debug, Serialize)]
pub struct DemoSessionDetail {
    #[serde(flatten)]
    pub summary: DemoSessionSummary,
    pub scenario: &'static DemoScenario,
    pub metrics: MetricsSnapshot,
    pub flows: Vec<FlowSnapshot>,
    pub events: Vec<DetectionEvent>,
    pub enforcement: DemoEnforcementInfo,
    pub isolation: &'static DemoIsolation,
}

impl DemoSession {
    fn new(
        id: String,
        scenario: &'static DemoScenario,
        speed: f64,
        now_ms: u64,
    ) -> Result<Arc<Self>, DemoError> {
        Ok(Arc::new(Self {
            id,
            scenario,
            runtime: Mutex::new(DemoRuntime::new(scenario, speed, now_ms)?),
            last_access_ms: AtomicU64::new(now_ms),
        }))
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn scenario(&self) -> &'static DemoScenario {
        self.scenario
    }

    pub fn touch(&self, now_ms: u64) {
        self.last_access_ms.store(now_ms, Ordering::Relaxed);
    }

    fn last_access(&self) -> u64 {
        self.last_access_ms.load(Ordering::Relaxed)
    }

    fn expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_access()) >= SESSION_TTL_MS
    }

    fn state(&self) -> PlaybackState {
        self.runtime.lock().state
    }

    fn interval_ms(&self, speed: f64) -> u64 {
        let interval = (self.scenario.base_step_ms as f64 / speed).round() as u64;
        interval.max(50)
    }

    pub fn pause(&self, now_ms: u64) -> Result<(), DemoError> {
        let mut runtime = self.runtime.lock();
        if runtime.state != PlaybackState::Playing {
            return Err(DemoError::InvalidState(
                "pause is only available while playback is running",
            ));
        }
        runtime.state = PlaybackState::Paused;
        runtime.updated_ms = now_ms;
        Ok(())
    }

    pub fn resume(&self, now_ms: u64) -> Result<(), DemoError> {
        let mut runtime = self.runtime.lock();
        if runtime.state != PlaybackState::Paused {
            return Err(DemoError::InvalidState(
                "resume is only available while playback is paused",
            ));
        }
        runtime.state = PlaybackState::Playing;
        runtime.next_due_ms = now_ms.saturating_add(100);
        runtime.updated_ms = now_ms;
        Ok(())
    }

    pub fn set_speed(&self, speed: f64, now_ms: u64) -> Result<(), DemoError> {
        let speed = validate_speed(speed)?;
        let mut runtime = self.runtime.lock();
        runtime.speed = speed;
        runtime.next_due_ms = now_ms.saturating_add(self.interval_ms(speed));
        runtime.updated_ms = now_ms;
        Ok(())
    }

    pub fn reset(&self, now_ms: u64) -> Result<(), DemoError> {
        let speed = self.runtime.lock().speed;
        let replacement = DemoRuntime::new(self.scenario, speed, now_ms)?;
        *self.runtime.lock() = replacement;
        self.touch(now_ms);
        Ok(())
    }

    fn advance(&self, now_ms: u64) {
        let mut runtime = self.runtime.lock();
        if runtime.state != PlaybackState::Playing {
            return;
        }
        let interval = self.interval_ms(runtime.speed);
        let mut steps = 0usize;
        while runtime.cursor < runtime.frames.len()
            && now_ms >= runtime.next_due_ms
            && steps < MAX_STEPS_PER_TICK
        {
            let frame = runtime.frames[runtime.cursor].clone();
            runtime
                .engine
                .process_link_frame(frame.link_type, &frame.data, frame.timestamp);
            runtime.cursor += 1;
            runtime.next_due_ms = runtime.next_due_ms.saturating_add(interval);
            steps += 1;
        }
        if runtime.cursor >= runtime.frames.len() {
            match runtime.hold_until_ms {
                Some(hold) if now_ms >= hold => {
                    runtime.state = PlaybackState::Completed;
                }
                Some(_) => {}
                None => {
                    runtime.hold_until_ms = Some(now_ms.saturating_add(COMPLETION_HOLD_MS));
                }
            }
        }
        if now_ms.saturating_sub(runtime.last_sample_ms) >= SAMPLE_INTERVAL_MS {
            runtime.engine.telemetry().metrics.sample();
            runtime.last_sample_ms = now_ms;
        }
        runtime.updated_ms = now_ms;
    }

    fn parts(&self) -> (Arc<Engine>, PlaybackState, f64, usize, usize, u64, u64) {
        let runtime = self.runtime.lock();
        (
            Arc::clone(&runtime.engine),
            runtime.state,
            runtime.speed,
            runtime.cursor,
            runtime.frames.len(),
            runtime.created_ms,
            runtime.updated_ms,
        )
    }

    fn summary_parts(&self, now_ms: u64) -> (DemoSessionSummary, Arc<Engine>) {
        let (engine, state, speed, processed, total, created, updated) = self.parts();
        let metrics = engine.telemetry().metrics.snapshot(engine.active_flows());
        let simulated_drops = engine
            .telemetry()
            .events
            .recent(512)
            .iter()
            .filter(|event| matches!(event.action.as_str(), "drop" | "reject") && !event.blocked)
            .count() as u64;
        let progress = if total == 0 {
            0.0
        } else {
            (processed as f32 / total as f32).clamp(0.0, 1.0)
        };
        self.touch(now_ms);
        (
            DemoSessionSummary {
                id: self.id.clone(),
                scenario_id: self.scenario.id,
                scenario_title: self.scenario.title,
                state,
                speed,
                created_ms: created,
                updated_ms: updated,
                progress,
                processed_frames: processed,
                total_frames: total,
                packets: metrics.packets_total,
                bytes: metrics.bytes_total,
                active_flows: metrics.active_flows,
                detections: metrics.detections_total,
                simulated_drops,
            },
            engine,
        )
    }

    pub fn summary(&self, now_ms: u64) -> DemoSessionSummary {
        self.summary_parts(now_ms).0
    }

    pub fn detail(&self, flow_limit: usize, event_limit: usize, now_ms: u64) -> DemoSessionDetail {
        let (summary, engine) = self.summary_parts(now_ms);
        let metrics = engine.telemetry().metrics.snapshot(engine.active_flows());
        DemoSessionDetail {
            summary,
            scenario: self.scenario,
            flows: engine.snapshot_flows(flow_limit.clamp(1, 500)),
            events: engine.telemetry().events.recent(event_limit.clamp(1, 500)),
            metrics,
            enforcement: DemoEnforcementInfo {
                mode: engine.mode().to_string(),
                can_enforce: engine.can_enforce(),
                enforcement_active: engine.enforcement_active(),
                simulated: true,
                note: "Passive monitor mode: rule verdicts are evaluated and displayed, but no \
                       packet is dropped and no host firewall or NFQUEUE state is touched.",
            },
            isolation: &ISOLATION,
        }
    }

    pub fn flows(&self, limit: usize, now_ms: u64) -> Vec<FlowSnapshot> {
        let (engine, ..) = self.parts();
        self.touch(now_ms);
        engine.snapshot_flows(limit.clamp(1, 500))
    }

    pub fn events(&self, limit: usize, now_ms: u64) -> Vec<DetectionEvent> {
        let (engine, ..) = self.parts();
        self.touch(now_ms);
        engine.telemetry().events.recent(limit.clamp(1, 500))
    }
}

pub struct DemoManager {
    sessions: RwLock<HashMap<String, Arc<DemoSession>>>,
    max_sessions: usize,
    next_id: AtomicU64,
}

impl DemoManager {
    pub fn new(max_sessions: usize) -> Arc<Self> {
        Arc::new(Self {
            sessions: RwLock::new(HashMap::new()),
            max_sessions: max_sessions.clamp(1, MAX_DEMO_SESSIONS),
            next_id: AtomicU64::new(1),
        })
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }

    pub fn session_ttl_seconds(&self) -> u64 {
        SESSION_TTL_MS / 1000
    }

    pub fn create(
        &self,
        scenario_id: &str,
        speed: Option<f64>,
    ) -> Result<Arc<DemoSession>, DemoError> {
        let scenario = scenario(scenario_id)
            .ok_or_else(|| DemoError::UnknownScenario(scenario_id.to_string()))?;
        let speed = validate_speed(speed.unwrap_or(1.0))?;
        let now = unix_ms();
        let mut sessions = self.sessions.write();
        sessions.retain(|_, session| !session.expired(now));
        if sessions.len() >= self.max_sessions {
            let victim = sessions
                .iter()
                .filter(|(_, session)| session.state() != PlaybackState::Playing)
                .min_by_key(|(_, session)| session.last_access())
                .map(|(id, _)| id.clone());
            if let Some(id) = victim {
                sessions.remove(&id);
            }
        }
        if sessions.len() >= self.max_sessions {
            return Err(DemoError::TooManySessions(self.max_sessions));
        }
        let id = format!(
            "demo-{now:x}-{:x}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        );
        let session = DemoSession::new(id.clone(), scenario, speed, now)?;
        sessions.insert(id, Arc::clone(&session));
        Ok(session)
    }

    pub fn get(&self, id: &str) -> Result<Arc<DemoSession>, DemoError> {
        let session = self
            .sessions
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| DemoError::NotFound(id.to_string()))?;
        let now = unix_ms();
        if session.expired(now) {
            self.sessions.write().remove(id);
            return Err(DemoError::NotFound(id.to_string()));
        }
        session.touch(now);
        Ok(session)
    }

    /// Remove a session. Used by the dashboard's Stop control.
    pub fn stop(&self, id: &str) -> Result<Arc<DemoSession>, DemoError> {
        let session = self
            .sessions
            .write()
            .remove(id)
            .ok_or_else(|| DemoError::NotFound(id.to_string()))?;
        Ok(session)
    }

    pub fn sessions(&self) -> Vec<DemoSessionSummary> {
        let now = unix_ms();
        {
            let mut sessions = self.sessions.write();
            sessions.retain(|_, session| !session.expired(now));
        }
        let mut sessions: Vec<Arc<DemoSession>> = self.sessions.read().values().cloned().collect();
        sessions.sort_by_key(|session| {
            let runtime = session.runtime.lock();
            (runtime.created_ms, session.id.clone())
        });
        sessions
            .into_iter()
            .map(|session| session.summary(now))
            .collect()
    }

    /// Advance sessions using a caller-supplied clock. Kept public so tests and
    /// embedders can drive deterministic playback without a Tokio timer.
    pub fn tick_at(&self, now_ms: u64) {
        let sessions: Vec<Arc<DemoSession>> = self.sessions.read().values().cloned().collect();
        for session in &sessions {
            session.advance(now_ms);
        }
        self.sessions
            .write()
            .retain(|_, session| !session.expired(now_ms));
    }

    pub fn spawn_ticker(self: &Arc<Self>) -> JoinHandle<()> {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(TICK_MS));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let Some(manager) = weak.upgrade() else {
                    break;
                };
                manager.tick_at(unix_ms());
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager(max: usize) -> Arc<DemoManager> {
        DemoManager::new(max)
    }

    fn run_to_completion(session: &DemoSession, start: u64) {
        let mut now = start;
        for _ in 0..400 {
            session.advance(now);
            if session.state() == PlaybackState::Completed {
                return;
            }
            now += 100;
        }
        panic!("demo session did not complete");
    }

    #[test]
    fn every_scenario_has_embedded_packets_and_isolated_engine() {
        assert_eq!(scenarios().len(), 7);
        for scenario in scenarios() {
            let manager = manager(4);
            let session = manager.create(scenario.id, Some(1.0)).unwrap();
            let (engine, state, speed, _, total, _, _) = session.parts();
            assert_eq!(state, PlaybackState::Playing);
            assert!((speed - 1.0).abs() < f64::EPSILON);
            assert!(total > 0);
            assert!(!engine.can_enforce());
            assert_eq!(engine.mode(), Mode::Monitor);
            assert!(!engine.enforcement_active());
            assert_eq!(engine.backend(), "demo-replay");
        }
    }

    #[test]
    fn normal_https_classification_is_real_and_not_proxy() {
        let manager = manager(4);
        let session = manager.create("normal-https", Some(1.0)).unwrap();
        let start = unix_ms();
        run_to_completion(&session, start);
        let detail = session.detail(20, 20, start + 10_000);
        assert_eq!(detail.flows.len(), 1);
        let flow = &detail.flows[0];
        assert_eq!(flow.sni.as_deref(), Some("www.example.com"));
        assert_eq!(flow.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(flow.tls_version.as_deref(), Some("TLS 1.3"));
        assert!(flow.tls_ja3.is_some());
        assert_eq!(flow.action, "allow");
        assert_eq!(flow.proxy_score, 0.0);
        assert!(flow
            .detected_protocols
            .iter()
            .any(|protocol| protocol == "tls"));
        assert!(detail.events.is_empty());
    }

    #[test]
    fn socks5_classifier_output_and_decision_are_visible() {
        let manager = manager(4);
        let session = manager.create("socks5-proxy", Some(1.0)).unwrap();
        let start = unix_ms();
        run_to_completion(&session, start);
        let detail = session.detail(20, 20, start + 10_000);
        assert_eq!(detail.flows.len(), 1);
        let flow = &detail.flows[0];
        assert!(flow
            .detected_protocols
            .iter()
            .any(|protocol| protocol == "socks5"));
        assert!(flow.proxy_score > 0.9);
        assert_eq!(flow.action, "drop");
        assert!(!flow.blocked);
        assert_eq!(detail.events.len(), 1);
        let event = &detail.events[0];
        assert_eq!(event.action, "drop");
        assert!(!event.blocked);
        assert!(event
            .evidence
            .iter()
            .any(|evidence| evidence.contains("example.com:443")));
        assert_eq!(detail.summary.simulated_drops, 1);
    }

    #[test]
    fn plaintext_vless_and_trojan_are_both_detected() {
        let manager = manager(4);
        let session = manager.create("vless-trojan", Some(1.0)).unwrap();
        let start = unix_ms();
        run_to_completion(&session, start);
        let detail = session.detail(20, 20, start + 10_000);
        let protocols: Vec<String> = detail
            .flows
            .iter()
            .flat_map(|flow| flow.detected_protocols.clone())
            .collect();
        assert!(protocols.iter().any(|p| p == "xray-vless"));
        assert!(protocols.iter().any(|p| p == "trojan-plaintext"));
        assert!(detail.events.iter().all(|event| event.action == "drop"));
    }

    #[test]
    fn dns_and_http_metadata_is_extracted() {
        let manager = manager(4);
        let session = manager.create("dns-http", Some(1.0)).unwrap();
        let start = unix_ms();
        run_to_completion(&session, start);
        let detail = session.detail(20, 20, start + 10_000);
        let dns = detail
            .flows
            .iter()
            .find(|flow| flow.dns_names.iter().any(|name| name == "www.example.com"))
            .expect("DNS flow");
        assert_eq!(dns.dns_qtype.as_deref(), Some("A"));
        let http = detail
            .flows
            .iter()
            .find(|flow| flow.http_method.as_deref() == Some("GET"))
            .expect("HTTP flow");
        assert_eq!(http.http_host.as_deref(), Some("example.com"));
        assert_eq!(http.detected_protocols, vec!["http1".to_string()]);
        assert_eq!(detail.events.len(), 2);
        assert!(detail.events.iter().all(|event| !event.blocked));
    }

    #[test]
    fn enforcement_scenario_uses_allow_monitor_log_and_drop_rules() {
        let manager = manager(4);
        let session = manager.create("traffic-enforcement", Some(1.0)).unwrap();
        let start = unix_ms();
        run_to_completion(&session, start);
        let detail = session.detail(20, 20, start + 10_000);
        let mut rules: Vec<&str> = detail
            .events
            .iter()
            .filter_map(|event| event.matched_rule.as_deref())
            .collect();
        rules.sort_unstable();
        assert!(rules.contains(&"allow-trusted-https"));
        assert!(rules.contains(&"monitor-dns-queries"));
        assert!(rules.contains(&"log-http-requests"));
        assert!(rules.contains(&"drop-plaintext-proxies"));
        assert!(detail.events.iter().all(|event| !event.blocked));
        assert!(!detail.enforcement.can_enforce);
        assert!(!detail.enforcement.enforcement_active);
    }

    #[test]
    fn mixed_scenario_interleaves_all_fixtures() {
        let manager = manager(4);
        let session = manager.create("mixed-traffic", Some(1.0)).unwrap();
        let start = unix_ms();
        run_to_completion(&session, start);
        let detail = session.detail(50, 50, start + 10_000);
        let protocols: Vec<String> = detail
            .flows
            .iter()
            .flat_map(|flow| flow.detected_protocols.clone())
            .collect();
        for expected in [
            "tls",
            "dns",
            "http1",
            "socks5",
            "http-connect",
            "xray-vless",
            "trojan-plaintext",
        ] {
            assert!(
                protocols.iter().any(|protocol| protocol == expected),
                "missing {expected} in mixed scenario"
            );
        }
        assert!(detail.metrics.packets_total >= 8);
        assert!(!detail.metrics.history.is_empty());
        assert!(detail.events.iter().any(|event| event.action == "drop"));
        assert!(
            detail.flows.iter().any(|flow| {
                flow.client.ends_with(":53001")
                    && flow.dns_names.iter().any(|name| name == "www.example.com")
            }),
            "out-of-order fragmented DNS flow should be reassembled"
        );
    }

    #[test]
    fn pause_resume_reset_and_speed_are_bounded() {
        let manager = manager(4);
        let session = manager.create("mixed-traffic", Some(1.0)).unwrap();
        let start = unix_ms();
        session.advance(start + 300);
        manager.tick_at(start + 500);
        session.pause(start + 600).unwrap();
        assert_eq!(session.state(), PlaybackState::Paused);
        let before = session.summary(start + 700).processed_frames;
        manager.tick_at(start + 5_000);
        let paused = session.summary(start + 5_000).processed_frames;
        assert_eq!(before, paused);
        assert!(session.pause(start + 5_100).is_err());
        session.resume(start + 5_200).unwrap();
        manager.tick_at(start + 5_300);
        let resumed = session.summary(start + 5_300).processed_frames;
        assert!(resumed >= paused);
        session.set_speed(2.0, start + 5_400).unwrap();
        assert!((session.summary(start + 5_400).speed - 2.0).abs() < f64::EPSILON);
        assert!(session.set_speed(100.0, start + 5_500).is_err());
        session.reset(start + 5_600).unwrap();
        let reset = session.summary(start + 5_600);
        assert_eq!(reset.state, PlaybackState::Playing);
        assert_eq!(reset.processed_frames, 0);
        assert_eq!(reset.packets, 0);
    }

    #[test]
    fn session_limit_and_stop_are_enforced() {
        let manager = manager(2);
        let first = manager.create("normal-https", Some(1.0)).unwrap();
        let second = manager.create("socks5-proxy", Some(1.0)).unwrap();
        let error = match manager.create("http-connect", Some(1.0)) {
            Ok(_) => panic!("session limit was not enforced"),
            Err(error) => error,
        };
        assert!(matches!(error, DemoError::TooManySessions(2)));
        manager.stop(first.id()).unwrap();
        assert!(manager.get(first.id()).is_err());
        manager
            .create("http-connect", Some(1.0))
            .expect("slot freed by stop");
        assert_eq!(manager.sessions().len(), 2);
        let _ = second;
    }

    #[test]
    fn unknown_scenario_and_invalid_speed_are_rejected() {
        let manager = manager(2);
        assert!(matches!(
            manager.create("../../etc/passwd", None),
            Err(DemoError::UnknownScenario(_))
        ));
        assert!(matches!(
            manager.create("normal-https", Some(f64::NAN)),
            Err(DemoError::InvalidSpeed(_))
        ));
    }

    #[test]
    fn replay_output_is_reproducible_across_sessions() {
        fn run() -> Vec<(String, Vec<String>, u32, String, bool)> {
            let manager = manager(2);
            let session = manager.create("vless-trojan", Some(2.0)).unwrap();
            let start = unix_ms();
            run_to_completion(&session, start);
            let mut flows: Vec<_> = session
                .detail(20, 20, start + 10_000)
                .flows
                .into_iter()
                .map(|flow| {
                    (
                        flow.client,
                        flow.detected_protocols,
                        (flow.confidence * 1000.0).round() as u32,
                        flow.action,
                        flow.blocked,
                    )
                })
                .collect();
            flows.sort_by(|a, b| a.0.cmp(&b.0));
            flows
        }
        assert_eq!(run(), run());
    }

    #[test]
    fn inactive_sessions_expire_and_release_their_engines() {
        let manager = manager(2);
        let session = manager.create("normal-https", Some(1.0)).unwrap();
        let id = session.id().to_string();
        manager.tick_at(unix_ms() + SESSION_TTL_MS + 1);
        assert!(manager.get(&id).is_err());
        assert!(manager.sessions().is_empty());
    }

    #[test]
    fn demo_engine_does_not_emit_in_rules_context() {
        // Guard against accidental production coupling: demo engines use an
        // internal rule store whose path is never reloaded by the API.
        let session = manager(2)
            .create("socks5-proxy", Some(1.0))
            .expect("session");
        let (engine, ..) = session.parts();
        assert_eq!(engine.config().general.mode, Mode::Monitor);
        assert!(!engine.config().api.enabled);
        assert!(engine.config().capture.pcap_file.is_none());
        assert_eq!(engine.flows().active_flows(), 0);
    }
}
