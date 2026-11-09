//! Original Rust DPI classifier.
//!
//! The classifier combines independent protocol parsers. Every finding carries
//! its own confidence and evidence so that policy can distinguish a decoded
//! SOCKS5 request from a weak TLS-mimicry heuristic. Encrypted payloads are
//! never treated as if their plaintext were visible.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::config::DetectionConfig;
use crate::packet::IpProtocol;
use crate::protocols::dns::{dns_type_name, parse_dns, DnsInfo};
use crate::protocols::http::{parse_http, HttpInfo};
use crate::protocols::http2::{parse_http2, Http2Info};
use crate::protocols::plaintext_proxy::{
    byte_entropy, parse_trojan, parse_vless, TrojanInfo, VlessInfo,
};
use crate::protocols::quic::{parse_quic, QuicInfo};
use crate::protocols::socks::{parse_socks, SocksInfo};
use crate::protocols::tls::{parse_tls, TlsInfo};
use crate::protocols::{looks_like_tls_record, MAX_INSPECT_BYTES};

pub const CAT_ENCRYPTED: &str = "encrypted";
pub const CAT_HTTP: &str = "http";
pub const CAT_DNS: &str = "dns";
pub const CAT_PROXY: &str = "proxy";
pub const CAT_PROXY_TRANSPORT: &str = "proxy_transport";
pub const CAT_OBFUSCATION: &str = "obfuscation";

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub protocol: String,
    pub category: String,
    pub confidence: f32,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct FlowAnalysis {
    pub findings: Vec<Finding>,
    pub detected_protocols: Vec<String>,
    pub primary_protocol: Option<String>,
    pub max_confidence: f32,
    pub proxy_score: f32,
    pub proxy_transport_score: f32,
    pub obfuscation_score: f32,
    pub category_scores: BTreeMap<String, f32>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub dns_names: Vec<String>,
    /// Compact TLS metadata retained after parser state is dropped.
    pub tls_version: Option<String>,
    pub tls_cipher_count: usize,
    pub tls_extension_count: usize,
    pub tls_grease_count: usize,
    pub tls_ech_present: bool,
    /// Compact HTTP metadata retained for dashboards and offline reports.
    pub http_method: Option<String>,
    pub http_host: Option<String>,
    pub http_target: Option<String>,
    /// DNS question type name (`A`, `AAAA`, ...).
    pub dns_qtype: Option<String>,
    pub tls: Option<TlsInfo>,
    pub http: Option<HttpInfo>,
    pub http2: Option<Http2Info>,
    pub dns: Option<DnsInfo>,
    pub quic: Option<QuicInfo>,
    pub socks: Option<SocksInfo>,
    pub vless: Option<VlessInfo>,
    pub trojan: Option<TrojanInfo>,
    pub evidence: Vec<String>,
    /// A handshake/header was cut short by the reassembled prefix. The engine
    /// re-runs classification when more contiguous bytes arrive.
    pub incomplete: bool,
}
impl FlowAnalysis {
    /// Drop detailed parser state after policy/event evaluation. Rule matching,
    /// flow snapshots and re-analysis only need the summary fields; retaining
    /// cipher lists, HPACK hints and per-protocol structs for every idle flow
    /// would multiply memory use.
    pub fn compact(&mut self) {
        if let Some(tls) = &mut self.tls {
            let ja3 = tls.ja3.take();
            let ja3_hash = tls.ja3_hash.take();
            *tls = TlsInfo {
                ja3,
                ja3_hash,
                ..Default::default()
            };
        }
        self.http = None;
        self.http2 = None;
        self.dns = None;
        self.quic = None;
        self.socks = None;
        self.vless = None;
        self.trojan = None;
        self.evidence.truncate(12);
        for finding in &mut self.findings {
            finding.evidence.truncate(6);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AnalysisInput<'a> {
    pub client_payload: &'a [u8],
    pub server_payload: &'a [u8],
    pub client_port: u16,
    pub server_port: u16,
    pub transport: IpProtocol,
    pub duration_ms: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
}

/// Extension point for Axion's classifier. Built-in detectors are ordinary
/// Rust modules; this trait lets applications or tests add bounded detectors
/// without a runtime plugin framework or external process.
pub trait ProtocolDetector: Send + Sync {
    fn name(&self) -> &'static str;
    fn inspect(&self, input: &AnalysisInput<'_>) -> Vec<Finding>;
}

/// Library-level classifier with optional extra detectors. The CLI uses an
/// empty extra set; all built-in logic remains in this module.
#[derive(Default)]
pub struct Classifier {
    detectors: Vec<Box<dyn ProtocolDetector>>,
}

impl Classifier {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<D: ProtocolDetector + 'static>(&mut self, detector: D) {
        self.detectors.push(Box::new(detector));
    }

    pub fn detector_names(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.name()).collect()
    }

    pub fn analyze(&self, input: AnalysisInput<'_>, config: &DetectionConfig) -> FlowAnalysis {
        let mut analysis = analyze(input, config);
        if self.detectors.is_empty() {
            return analysis;
        }
        for detector in &self.detectors {
            for finding in detector.inspect(&input) {
                add(
                    &mut analysis,
                    &finding.protocol,
                    &finding.category,
                    finding.confidence,
                    finding.evidence,
                );
            }
        }
        finalize(&mut analysis);
        analysis
    }
}

pub fn analyze(input: AnalysisInput<'_>, config: &DetectionConfig) -> FlowAnalysis {
    let client = &input.client_payload[..input.client_payload.len().min(MAX_INSPECT_BYTES)];
    let server = &input.server_payload[..input.server_payload.len().min(MAX_INSPECT_BYTES)];
    let mut out = FlowAnalysis::default();
    let tcp = input.transport == IpProtocol::TCP;
    let udp = input.transport == IpProtocol::UDP;

    // --- TLS ---------------------------------------------------------------
    let client_hello = parse_tls(client).filter(|t| t.handshake == "client_hello");
    let server_hello = if client_hello.is_some() {
        None
    } else {
        parse_tls(server)
    };
    let tls_info = client_hello;
    if let Some(info) = &tls_info {
        let version = info
            .supported_versions
            .iter()
            .copied()
            .max()
            .or(info.negotiated_version)
            .unwrap_or(info.legacy_version);
        let evidence = format!(
            "TLS {} ClientHello, {} ciphers, {} extensions",
            crate::protocols::tls::tls_version_name(version),
            info.cipher_suites.len(),
            info.extensions.len()
        );
        add(&mut out, "tls", CAT_ENCRYPTED, 0.99, vec![evidence]);
        out.incomplete |= info.truncated;
        out.sni = info.sni.clone();
        out.alpn = info.alpn.clone();
        out.tls_version = Some(crate::protocols::tls::tls_version_name(version).to_string());
        out.tls_cipher_count = info.cipher_suites.len();
        out.tls_extension_count = info.extensions.len();
        out.tls_grease_count = info.grease_count;
        out.tls_ech_present = info.ech_present;
        if info.ech_present {
            out.evidence
                .push("TLS Encrypted ClientHello extension present".to_string());
        }
        if let Some(sni) = &info.sni {
            out.evidence.push(format!("TLS SNI: {sni}"));
        }
        let mut stored = info.clone();
        if !config.enable_tls_fingerprint {
            stored.ja3 = None;
            stored.ja3_hash = None;
        }
        out.tls = Some(stored);
    } else if let Some(info) = server_hello {
        let version = info
            .negotiated_version
            .or(info.supported_versions.iter().copied().max())
            .unwrap_or(info.legacy_version);
        add(
            &mut out,
            "tls",
            CAT_ENCRYPTED,
            0.94,
            vec![format!(
                "TLS ServerHello ({}) with {} ciphers",
                crate::protocols::tls::tls_version_name(version),
                info.cipher_suites.len()
            )],
        );
        out.incomplete |= info.truncated;
        out.alpn = info.alpn.clone();
        out.tls_version = Some(crate::protocols::tls::tls_version_name(version).to_string());
        out.tls_cipher_count = info.cipher_suites.len();
        out.tls_extension_count = info.extensions.len();
        out.tls_grease_count = info.grease_count;
        out.tls_ech_present = info.ech_present;
        let mut stored = info;
        if !config.enable_tls_fingerprint {
            stored.ja3 = None;
            stored.ja3_hash = None;
        }
        out.tls = Some(stored);
    } else if looks_like_tls_record(client) {
        if crate::protocols::tls::tls_record_incomplete(client) {
            out.incomplete = true;
        }
        add(
            &mut out,
            "tls",
            CAT_ENCRYPTED,
            0.65,
            vec!["TLS record header (handshake not fully visible)".to_string()],
        );
    }

    // HTTP CONNECT can carry a TLS handshake after its header block. Extract
    // metadata that is visible in the same direction.
    let mut http_info = parse_http(client);
    if http_info.is_none() {
        http_info = parse_http(server);
    }
    if let Some(info) = http_info {
        out.incomplete |= info.truncated;
        out.http_method = info.method.clone();
        out.http_host = info.host.clone();
        out.http_target = info.target.clone();
        let confidence = if info.is_request { 0.97 } else { 0.90 };
        let target = info.target.clone().unwrap_or_default();
        let evidence = if info.is_request {
            format!(
                "{} {} {}",
                info.method.as_deref().unwrap_or("?"),
                target,
                info.version.as_deref().unwrap_or("")
            )
        } else {
            format!(
                "HTTP response {}",
                info.status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "?".to_string())
            )
        };
        add(&mut out, "http1", CAT_HTTP, confidence, vec![evidence]);
        if let Some(host) = &info.host {
            out.evidence.push(format!("HTTP host: {host}"));
        }
        if info.connect {
            add(
                &mut out,
                "http-connect",
                CAT_PROXY,
                0.97,
                vec![format!("HTTP CONNECT tunnel to {target}")],
            );
            if let Some(tail) = after_headers(client) {
                if let Some(tls) = parse_tls(tail) {
                    add(
                        &mut out,
                        "tls-in-connect",
                        CAT_ENCRYPTED,
                        0.98,
                        vec!["TLS handshake observed inside CONNECT tunnel".to_string()],
                    );
                    if out.sni.is_none() {
                        out.sni = tls.sni.clone();
                    }
                    if out.tls.is_none() {
                        out.tls = Some(tls);
                    }
                }
            }
        }
        if info.websocket {
            add(
                &mut out,
                "websocket",
                CAT_HTTP,
                0.96,
                vec![format!("WebSocket upgrade handshake on {target}")],
            );
            add(
                &mut out,
                "websocket-transport",
                CAT_PROXY_TRANSPORT,
                0.32,
                vec!["WebSocket is a common proxy transport (not proof by itself)".to_string()],
            );
        }
        out.http = Some(info);
    }

    // --- HTTP/2 and gRPC ---------------------------------------------------
    let h2 = parse_http2(client).or_else(|| parse_http2(server));
    if let Some(info) = h2 {
        out.incomplete |= info.truncated;
        let confidence = if info.preface { 0.99 } else { 0.82 };
        add(
            &mut out,
            "http2",
            CAT_HTTP,
            confidence,
            vec![format!(
                "HTTP/2 preface={} frames={}",
                info.preface, info.frame_count
            )],
        );
        if info.grpc_hint {
            add(
                &mut out,
                "grpc",
                CAT_HTTP,
                0.80,
                vec!["HTTP/2 application/grpc literal observed".to_string()],
            );
            add(
                &mut out,
                "grpc-transport",
                CAT_PROXY_TRANSPORT,
                0.30,
                vec!["gRPC is a supported proxy transport (not proof by itself)".to_string()],
            );
        }
        out.http2 = Some(info);
    }

    // --- DNS ---------------------------------------------------------------
    if let Some((dns, confidence)) = detect_dns(input, client, server, tcp, udp) {
        let name = dns
            .questions
            .first()
            .map(|q| q.name.clone())
            .unwrap_or_default();
        let qtype = dns
            .questions
            .first()
            .map(|q| dns_type_name(q.qtype))
            .unwrap_or("?");
        add(
            &mut out,
            "dns",
            CAT_DNS,
            confidence,
            vec![format!("DNS query {name} {qtype}")],
        );
        out.dns_names = dns.questions.iter().map(|q| q.name.clone()).collect();
        out.dns_names.extend(dns.answers.iter().cloned());
        out.dns_qtype = dns
            .questions
            .first()
            .map(|q| dns_type_name(q.qtype).to_string());
        out.dns = Some(dns);
    }

    // --- QUIC --------------------------------------------------------------
    if udp && config.enable_quic_initial {
        if let Some(info) = parse_quic(client) {
            let confidence = if info.client_hello.is_some() {
                0.99
            } else if info.decrypted {
                0.94
            } else if info.is_initial {
                0.84
            } else if info.version != 0 {
                0.55
            } else {
                0.40
            };
            let mut evidence = vec![format!(
                "QUIC {} long-header type {} dcid={}",
                info.version_name,
                info.packet_type,
                short(&info.dcid, 16)
            )];
            if info.client_hello.is_some() {
                evidence.push("QUIC Initial decrypted; TLS ClientHello recovered".to_string());
            }
            add(&mut out, "quic", CAT_ENCRYPTED, confidence, evidence);
            if let Some(hello) = &info.client_hello {
                if out.sni.is_none() {
                    out.sni = hello.sni.clone();
                }
                if out.alpn.is_empty() {
                    out.alpn = hello.alpn.clone();
                }
                if let Some(sni) = &hello.sni {
                    out.evidence.push(format!("QUIC SNI: {sni}"));
                }
            }
            out.quic = Some(info);
        }
    }

    // --- SOCKS -------------------------------------------------------------
    if tcp {
        if let Some(info) = parse_socks(client, true) {
            let confidence = if info.stage == "request" { 0.97 } else { 0.72 };
            let protocol = if info.version == 5 {
                "socks5"
            } else {
                "socks4"
            };
            let mut evidence = vec![format!("SOCKS{} {} handshake", info.version, info.stage)];
            if let Some(addr) = &info.address {
                evidence.push(format!("target {}:{}", addr, info.port.unwrap_or_default()));
            }
            add(&mut out, protocol, CAT_PROXY, confidence, evidence);
            out.socks = Some(info);
        }
    } else if udp {
        if let Some(info) = parse_socks(client, false) {
            add(
                &mut out,
                "socks5-udp",
                CAT_PROXY,
                0.80,
                vec!["SOCKS5 UDP request header".to_string()],
            );
            out.socks = Some(info);
        }
    }

    // --- Plaintext VLESS / Trojan -----------------------------------------
    if tcp {
        if let Some(info) = parse_vless(client) {
            let confidence = if info.uuid_v4_like { 0.95 } else { 0.84 };
            let mut evidence = vec![format!(
                "VLESS request version={} command={} target={}:{} ({})",
                info.version, info.command, info.address, info.port, info.address_type
            )];
            if info.addons_len > 0 {
                evidence.push(format!("VLESS addons length {}", info.addons_len));
            }
            add(&mut out, "xray-vless", CAT_PROXY, confidence, evidence);
            out.vless = Some(info);
        }
        if let Some(info) = parse_trojan(client) {
            add(
                &mut out,
                "trojan-plaintext",
                CAT_PROXY,
                0.97,
                vec![format!(
                    "Trojan request command={} target={}:{} ({})",
                    info.command, info.address, info.port, info.address_type
                )],
            );
            out.trojan = Some(info);
        }
    }

    // --- Heuristics (never treated as proof) ------------------------------
    if config.enable_heuristics {
        if let Some(tls) = out.tls.clone() {
            tls_heuristics(&mut out, &tls, &input);
        }
        if out.findings.is_empty() && tcp {
            let sample = &client[..client.len().min(4096)];
            let entropy = byte_entropy(sample);
            if sample.len() >= 96 && entropy >= 7.45 {
                let mut confidence = 0.16;
                if matches!(input.server_port, 80 | 443 | 8080 | 8443) {
                    confidence += 0.04;
                }
                add(
                    &mut out,
                    "vmess-suspected",
                    CAT_OBFUSCATION,
                    confidence,
                    vec![format!(
                        "opaque high-entropy stream (entropy {entropy:.2} bits/byte); VMess is encrypted, this is not proof"
                    )],
                );
            }
        }
    }

    finalize(&mut out);
    out
}

fn detect_dns(
    input: AnalysisInput<'_>,
    client: &[u8],
    server: &[u8],
    tcp: bool,
    udp: bool,
) -> Option<(DnsInfo, f32)> {
    if !tcp && !udp {
        return None;
    }
    let dns_port = input.server_port == 53
        || input.client_port == 53
        || input.server_port == 5353
        || input.client_port == 5353;
    if udp {
        if let Some(dns) = parse_dns(client, false).or_else(|| parse_dns(server, false)) {
            return Some((dns, if dns_port { 0.97 } else { 0.62 }));
        }
    }
    if tcp && dns_port {
        if let Some(dns) = parse_dns(client, true).or_else(|| parse_dns(server, true)) {
            return Some((dns, 0.95));
        }
    }
    None
}

fn tls_heuristics(out: &mut FlowAnalysis, tls: &TlsInfo, input: &AnalysisInput<'_>) {
    if tls.handshake != "client_hello" {
        return;
    }
    let tls13 = tls.supported_versions.contains(&0x0304)
        || tls.negotiated_version == Some(0x0304)
        || tls.legacy_version == 0x0303;
    let h2_alpn = tls.alpn.iter().any(|a| a == "h2");
    let mut score = 0.0f32;
    let mut evidence = Vec::new();
    if tls13 {
        score += 0.05;
        evidence.push("TLS 1.3".to_string());
    }
    if tls.grease_count > 0 {
        score += 0.06;
        evidence.push("GREASE values in ClientHello".to_string());
    }
    if h2_alpn && tls.alpn.len() >= 2 {
        score += 0.04;
        evidence.push("h2 + HTTP/1.1 ALPN mix".to_string());
    }
    if tls.session_id_len == 32 {
        score += 0.02;
        evidence.push("32-byte compatibility session ID".to_string());
    }
    if tls.ech_present {
        score += 0.02;
        evidence.push("ECH offered".to_string());
    }
    if score > 0.0 {
        score = (score + 0.06).min(0.28);
        evidence.push(
            "uTLS/REALITY also exhibit these features; ordinary browsers do too (weak indicator)"
                .to_string(),
        );
        add(out, "reality-suspected", CAT_OBFUSCATION, score, evidence);
    }
    let total_bytes = input.client_bytes + input.server_bytes;
    if tls13 && input.duration_ms > 5_000 && total_bytes > 512 * 1024 {
        add(
            out,
            "xtls-suspected",
            CAT_OBFUSCATION,
            0.15,
            vec![format!(
                "long-lived TLS 1.3 flow ({} bytes, {} ms); video/legitimate TLS also matches",
                total_bytes, input.duration_ms
            )],
        );
    }
}

fn add(
    out: &mut FlowAnalysis,
    protocol: &str,
    category: &str,
    confidence: f32,
    evidence: Vec<String>,
) {
    let confidence = confidence.clamp(0.0, 1.0);
    if let Some(existing) = out.findings.iter_mut().find(|f| f.protocol == protocol) {
        if confidence > existing.confidence {
            existing.confidence = confidence;
        }
        for item in evidence {
            if !existing.evidence.contains(&item) {
                existing.evidence.push(item);
            }
        }
        return;
    }
    out.findings.push(Finding {
        protocol: protocol.to_string(),
        category: category.to_string(),
        confidence,
        evidence,
    });
}

fn finalize(out: &mut FlowAnalysis) {
    let mut category_findings: BTreeMap<String, Vec<f32>> = BTreeMap::new();
    for finding in &out.findings {
        category_findings
            .entry(finding.category.clone())
            .or_default()
            .push(finding.confidence);
        if !out.detected_protocols.contains(&finding.protocol) {
            out.detected_protocols.push(finding.protocol.clone());
        }
        out.max_confidence = out.max_confidence.max(finding.confidence);
    }
    for (category, scores) in category_findings {
        out.category_scores.insert(category, noisy_or(&scores));
    }
    out.proxy_score = out.category_scores.get(CAT_PROXY).copied().unwrap_or(0.0);
    out.proxy_transport_score = out
        .category_scores
        .get(CAT_PROXY_TRANSPORT)
        .copied()
        .unwrap_or(0.0);
    out.obfuscation_score = out
        .category_scores
        .get(CAT_OBFUSCATION)
        .copied()
        .unwrap_or(0.0);
    out.findings.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out.primary_protocol = out.findings.first().map(|f| f.protocol.clone());
    for finding in &out.findings {
        for evidence in &finding.evidence {
            if !out.evidence.contains(evidence) {
                out.evidence.push(evidence.clone());
            }
        }
    }
}

pub fn noisy_or(scores: &[f32]) -> f32 {
    let miss: f32 = scores
        .iter()
        .fold(1.0f32, |acc, score| acc * (1.0 - score.clamp(0.0, 1.0)));
    (1.0 - miss).clamp(0.0, 1.0)
}

fn after_headers(data: &[u8]) -> Option<&[u8]> {
    let end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    data.get(end + 4..)
}

fn short(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}…", &value[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::test_utils::client_hello;

    fn config() -> DetectionConfig {
        DetectionConfig::default()
    }

    fn input<'a>(client: &'a [u8], server: &'a [u8]) -> AnalysisInput<'a> {
        AnalysisInput {
            client_payload: client,
            server_payload: server,
            client_port: 50000,
            server_port: 443,
            transport: IpProtocol::TCP,
            duration_ms: 100,
            client_bytes: client.len() as u64,
            server_bytes: server.len() as u64,
        }
    }

    #[test]
    fn classifies_benign_tls_without_proxy_finding() {
        let hello = client_hello("www.example.com", &["h2", "http/1.1"], 0x0304);
        let a = analyze(input(&hello, &[]), &config());
        assert!(a.detected_protocols.contains(&"tls".to_string()));
        assert_eq!(a.sni.as_deref(), Some("www.example.com"));
        assert_eq!(a.proxy_score, 0.0);
    }

    #[test]
    fn classifies_http_connect_as_proxy() {
        let request = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let a = analyze(input(request, &[]), &config());
        assert!(a.proxy_score > 0.9);
        assert!(a.detected_protocols.contains(&"http-connect".to_string()));
    }

    #[test]
    fn classifies_socks5_and_extracts_request() {
        let mut data = vec![5, 1, 0, 5, 1, 0, 3, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        let a = analyze(input(&data, &[]), &config());
        assert!(a.detected_protocols.contains(&"socks5".to_string()));
        assert!(a.proxy_score > 0.9);
    }

    #[test]
    fn classifies_plaintext_vless() {
        let mut data = vec![0u8];
        data.extend_from_slice(&[
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ]);
        data.push(0);
        data.push(1);
        data.extend_from_slice(&443u16.to_be_bytes());
        data.push(2);
        data.push(11);
        data.extend_from_slice(b"example.com");
        let a = analyze(input(&data, &[]), &config());
        assert!(a.detected_protocols.contains(&"xray-vless".to_string()));
        assert!(a.proxy_score >= 0.9);
    }

    #[test]
    fn encrypted_tls_is_not_labelled_vmess() {
        let hello = client_hello("example.com", &["h2"], 0x0304);
        let a = analyze(input(&hello, &[]), &config());
        assert!(!a
            .detected_protocols
            .contains(&"vmess-suspected".to_string()));
    }

    #[test]
    fn noisy_or_is_bounded() {
        assert!((noisy_or(&[0.5, 0.5]) - 0.75).abs() < 0.001);
        assert_eq!(noisy_or(&[]), 0.0);
    }

    #[test]
    fn compact_preserves_rule_snapshot_fields() {
        let hello = client_hello("www.example.com", &["h2"], 0x0304);
        let mut a = analyze(input(&hello, &[]), &config());
        let ja3 = a.tls.as_ref().and_then(|t| t.ja3_hash.clone());
        assert!(ja3.is_some());
        a.compact();
        assert_eq!(a.tls.as_ref().and_then(|t| t.ja3_hash.clone()), ja3);
        assert!(a.http.is_none());
        assert_eq!(a.sni.as_deref(), Some("www.example.com"));
        assert!(a.detected_protocols.contains(&"tls".to_string()));
    }

    #[test]
    fn tls_fingerprint_can_be_disabled() {
        let hello = client_hello("www.example.com", &["h2"], 0x0304);
        let mut cfg = config();
        cfg.enable_tls_fingerprint = false;
        let a = analyze(input(&hello, &[]), &cfg);
        let tls = a.tls.expect("tls metadata");
        assert!(tls.ja3.is_none());
        assert!(tls.ja3_hash.is_none());
    }

    #[test]
    fn custom_detector_extends_classifier() {
        struct Custom;
        impl ProtocolDetector for Custom {
            fn name(&self) -> &'static str {
                "custom"
            }

            fn inspect(&self, _input: &AnalysisInput<'_>) -> Vec<Finding> {
                vec![Finding {
                    protocol: "custom-proxy".into(),
                    category: CAT_PROXY.into(),
                    confidence: 0.8,
                    evidence: vec!["synthetic detector".into()],
                }]
            }
        }
        let mut classifier = Classifier::new();
        classifier.register(Custom);
        let hello = client_hello("www.example.com", &["h2"], 0x0304);
        let analysis = classifier.analyze(input(&hello, &[]), &config());
        assert!(analysis
            .detected_protocols
            .contains(&"custom-proxy".to_string()));
        assert!((analysis.proxy_score - 0.8).abs() < 0.001);
        assert_eq!(classifier.detector_names(), vec!["custom"]);
    }
}
