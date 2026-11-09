use std::sync::Arc;
use std::time::SystemTime;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use axion::config::{Config, Mode};
use axion::engine::Engine;
use axion::packet::{parse_ethernet, LinkType};
use axion::protocols::dns::parse_dns;
use axion::protocols::http::parse_http;
use axion::protocols::socks::parse_socks;
use axion::protocols::test_utils::client_hello;
use axion::protocols::tls::parse_tls;
use axion::rules::RuleStore;
use axion::telemetry::Telemetry;

fn tcp_frame(payload: &[u8], sport: u16, dport: u16) -> Vec<u8> {
    let mut frame = vec![0u8; 14 + 20 + 20];
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    let ip = &mut frame[14..34];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&[192, 0, 2, 10]);
    ip[16..20].copy_from_slice(&[198, 51, 100, 20]);
    let tcp = &mut frame[34..54];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[4..8].copy_from_slice(&1u32.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    frame.extend_from_slice(payload);
    frame
}

fn dns_query() -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&0x1234u16.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    for label in ["www", "example", "com"] {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0);
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes());
    msg
}

fn benchmarks(c: &mut Criterion) {
    let hello = client_hello("www.example.com", &["h2", "http/1.1"], 0x0304);
    let tls_frame = tcp_frame(&hello, 50000, 443);
    let http = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\n\r\n";
    let socks = {
        let mut data = vec![5, 1, 0, 5, 1, 0, 3, 11];
        data.extend_from_slice(b"example.com");
        data.extend_from_slice(&443u16.to_be_bytes());
        data
    };
    let dns = dns_query();

    c.bench_function("parse_ethernet_ipv4_tcp_tls", |b| {
        b.iter(|| black_box(parse_ethernet(black_box(&tls_frame), None)))
    });
    c.bench_function("tls_client_hello", |b| {
        b.iter(|| black_box(parse_tls(black_box(&hello))))
    });
    c.bench_function("http_request", |b| {
        b.iter(|| black_box(parse_http(black_box(http))))
    });
    c.bench_function("socks5_request", |b| {
        b.iter(|| black_box(parse_socks(black_box(&socks), true)))
    });
    c.bench_function("dns_query", |b| {
        b.iter(|| black_box(parse_dns(black_box(&dns), false)))
    });

    let mut config = Config::default();
    config.general.mode = Mode::Monitor;
    config.firewall.bypass_cidrs.clear();
    config.firewall.bypass_tcp_ports.clear();
    let telemetry = Arc::new(Telemetry::new(10, 1000, 64));
    let rules = RuleStore::new("bench.toml".into(), &config).unwrap();
    let engine = Engine::new(Arc::new(config), rules, telemetry, false, "bench").unwrap();
    // Prime the flow and classification path.
    engine.process_link_frame(LinkType::Ethernet, &tls_frame, Some(SystemTime::now()));
    c.bench_function("engine_packet_existing_flow", |b| {
        b.iter(|| {
            black_box(engine.process_link_frame(LinkType::Ethernet, black_box(&tls_frame), None))
        })
    });
}

criterion_group!(benches, benchmarks);
criterion_main!(benches);
