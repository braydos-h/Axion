use std::collections::BTreeMap;
use std::net::IpAddr;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

use axion::config::{Config, MatchConfig, RuleConfig};
use axion::flow::reassembly::TcpReassembler;
use axion::flow::Direction;
use axion::packet::IpProtocol;
use axion::rules::{RuleContext, Rules};

fn chunk(seed: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add(i as u8)).collect()
}

fn sequential(c: &mut Criterion) {
    let chunks: Vec<Vec<u8>> = (0..64).map(|i| chunk(i as u8, 1460)).collect();
    c.bench_function("tcp_reassembly_in_order_64x1460", |b| {
        b.iter_batched(
            || TcpReassembler::new(256 * 1024),
            |mut reassembler| {
                for (index, data) in chunks.iter().enumerate() {
                    reassembler.push(1000 + (index * 1460) as u32, black_box(data));
                }
                black_box(reassembler.len())
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("tcp_reassembly_out_of_order_64x1460", |b| {
        b.iter_batched(
            || TcpReassembler::new(256 * 1024),
            |mut reassembler| {
                reassembler.observe_syn(999);
                for (index, data) in chunks.iter().enumerate().rev() {
                    reassembler.push(1000 + (index * 1460) as u32, black_box(data));
                }
                black_box(reassembler.len())
            },
            BatchSize::SmallInput,
        )
    });
}

fn rules_benchmark(c: &mut Criterion) {
    let config = Config {
        rules: (0..10)
            .map(|i| RuleConfig {
                name: format!("rule-{i}"),
                priority: i,
                matcher: MatchConfig {
                    ports: vec![443],
                    protocols: vec!["tls".into()],
                    sni: vec!["*.example.com".into()],
                    min_confidence: 0.5,
                    ..Default::default()
                },
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    };
    let rules = Rules::from_config(&config).unwrap();
    let protocols = vec!["tls".to_string()];
    let mut categories = BTreeMap::new();
    categories.insert("encrypted".to_string(), 0.99f32);
    let ctx = RuleContext {
        src: "192.0.2.10".parse::<IpAddr>().unwrap(),
        dst: "198.51.100.20".parse::<IpAddr>().unwrap(),
        src_port: 50000,
        dst_port: 443,
        transport: IpProtocol::TCP,
        direction: Direction::ClientToServer,
        protocols: &protocols,
        categories: &categories,
        confidence: 0.99,
        sni: Some("www.example.com"),
        dns_names: &[],
        total_bytes: 100_000,
        duration_ms: 1000,
        proxy_score: 0.0,
        proxy_transport_score: 0.0,
        obfuscation_score: 0.0,
    };
    c.bench_function("rules_10_priority_match", |b| {
        b.iter(|| black_box(rules.evaluate(black_box(&ctx))))
    });
}

criterion_group!(benches, sequential, rules_benchmark);
criterion_main!(benches);
