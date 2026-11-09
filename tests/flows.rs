//! End-to-end flow, reassembly and policy tests across multiple packets.

use std::sync::Arc;

use axion::config::{Action, Config, MatchConfig, Mode, RuleConfig};
use axion::engine::Engine;
use axion::packet::LinkType;
use axion::rules::RuleStore;
use axion::telemetry::Telemetry;

fn tcp_frame(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
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
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = flags;
    frame.extend_from_slice(payload);
    frame
}

fn engine(config: Config) -> Arc<Engine> {
    let telemetry = Arc::new(Telemetry::new(10, 1000, 64));
    let rules = RuleStore::new("tests-flows.toml".into(), &config).unwrap();
    Engine::new(Arc::new(config), rules, telemetry, true, "test").unwrap()
}

#[test]
fn out_of_order_tcp_reassembly_and_sni_rule() {
    let mut config = Config::default();
    config.general.mode = Mode::Enforce;
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    config.rules = vec![RuleConfig {
        name: "block-sni".into(),
        priority: 100,
        action: Action::Drop,
        enabled: true,
        log: true,
        matcher: MatchConfig {
            sni: vec!["*.blocked.example".into()],
            direction: axion::config::DirectionMatch::ClientToServer,
            min_confidence: 0.5,
            ..Default::default()
        },
        ..Default::default()
    }];
    let engine = engine(config);
    let hello = axion::protocols::test_utils::client_hello(
        "api.blocked.example",
        &["h2", "http/1.1"],
        0x0304,
    );
    let split = hello.len() / 2;

    // Establish the ISN, then deliver the second half before the first.
    let syn = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40000,
        443,
        999,
        0x02,
        b"",
    );
    let second = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40000,
        443,
        1000 + split as u32,
        0x18,
        &hello[split..],
    );
    let first = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40000,
        443,
        1000,
        0x18,
        &hello[..split],
    );
    assert!(
        !engine
            .process_link_frame(LinkType::Ethernet, &syn, None)
            .blocked
    );
    assert!(
        !engine
            .process_link_frame(LinkType::Ethernet, &second, None)
            .blocked
    );
    let result = engine.process_link_frame(LinkType::Ethernet, &first, None);
    assert!(
        result.blocked,
        "SNI should resolve after out-of-order reassembly: {result:?}"
    );
    assert_eq!(result.matched_rule.as_deref(), Some("block-sni"));

    let snapshots = engine.snapshot_flows(10);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].sni.as_deref(), Some("api.blocked.example"));
    assert!(snapshots[0].blocked);

    // Reverse-direction packets inherit the flow verdict.
    let reverse = tcp_frame(
        [198, 51, 100, 20],
        [192, 0, 2, 10],
        443,
        40000,
        5000,
        0x18,
        b"response",
    );
    let result = engine.process_link_frame(LinkType::Ethernet, &reverse, None);
    assert!(result.blocked);
}

#[test]
fn in_order_split_client_hello_is_reanalysed() {
    let mut config = Config::default();
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    let engine = engine(config);
    let hello = axion::protocols::test_utils::client_hello(
        "split.example.com",
        &["h2", "http/1.1"],
        0x0304,
    );
    let split = hello.len() / 2;
    let first = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        42000,
        443,
        1000,
        0x18,
        &hello[..split],
    );
    let second = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        42000,
        443,
        1000 + split as u32,
        0x18,
        &hello[split..],
    );
    engine.process_link_frame(LinkType::Ethernet, &first, None);
    let flows = engine.snapshot_flows(10);
    assert!(
        flows[0].incomplete,
        "partial TLS handshake should be incomplete"
    );
    engine.process_link_frame(LinkType::Ethernet, &second, None);
    let flows = engine.snapshot_flows(10);
    assert_eq!(flows[0].sni.as_deref(), Some("split.example.com"));
    assert!(!flows[0].incomplete);
}

#[test]
fn benign_tls_is_not_auto_blocked_by_weak_heuristics() {
    let mut config = Config::default();
    config.general.mode = Mode::Enforce;
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    let engine = engine(config);
    let hello =
        axion::protocols::test_utils::client_hello("www.example.com", &["h2", "http/1.1"], 0x0304);
    let frame = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 20],
        40000,
        443,
        1,
        0x18,
        &hello,
    );
    for _ in 0..3 {
        let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
        assert!(!result.blocked);
    }
    let flows = engine.snapshot_flows(10);
    assert_eq!(flows[0].proxy_score, 0.0);
    // The weak reality hypothesis is recorded in flows but does not block.
    assert!(flows[0]
        .detected_protocols
        .iter()
        .any(|p| p == "reality-suspected"));
}

#[test]
fn plaintext_connect_is_blocked_in_enforce_mode() {
    let mut config = Config::default();
    config.general.mode = Mode::Enforce;
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    let engine = engine(config);
    let payload = b"CONNECT attacker.example:443 HTTP/1.1\r\nHost: attacker.example:443\r\n\r\n";
    let frame = tcp_frame(
        [192, 0, 2, 10],
        [198, 51, 100, 30],
        41000,
        8080,
        1,
        0x18,
        payload,
    );
    let result = engine.process_link_frame(LinkType::Ethernet, &frame, None);
    assert!(result.blocked);
    assert_eq!(
        result.matched_rule.as_deref(),
        Some("builtin:auto-block-proxy")
    );
}
