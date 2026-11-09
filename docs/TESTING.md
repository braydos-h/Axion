# Testing and measurement

## Local/CI commands

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
node tests/web-ui.cjs
cargo bench --no-run --locked
cargo build --release --locked
bash scripts/smoke-test.sh target/release/axion
```

Privileged tests are ignored by default and skip if capabilities/kernel support
are absent:

```bash
sudo -E cargo test --test live_capture -- --ignored --nocapture
sudo -E cargo test --test enforcement -- --ignored --nocapture
```

- `live_capture` opens AF_PACKET (and libpcap when available) on `lo`, sends a
  UDP datagram, and asserts a frame is captured. It also binds/unbinds an
  NFQUEUE and verifies the nfnetlink config acknowledgements.
- `enforcement` creates a uniquely named nftables table, queues two loopback TCP
  ports, starts the real NFQUEUE loop, verifies an allowed handshake completes
  and a SYN matching a DROP rule does not, checks non-zero dropped-packet and
  zero enforcement-error counters, then removes the table in a guard. It skips if
  not root, if `nft` is missing, or if nfnetlink_queue cannot bind.

## Test layers

| Layer | Location | What it covers |
|---|---|---|
| Parser units | `src/**/tests` | Ethernet/VLAN, IPv4/IPv6, extension headers, TCP/UDP/ICMP, truncation, malformed lengths |
| Fragment/reassembly | `src/packet/fragment.rs`, `src/flow/reassembly.rs` | out-of-order, overlaps, wrap, caps, expiry, IPv4+IPv6 fragments |
| Protocol units | `src/protocols/*` | TLS SNI/ALPN/fingerprint, HTTP, WebSocket, H2/gRPC hint, DNS pointers, SOCKS4/5, VLESS/Trojan, QUIC decryption |
| Classifier/scoring | `src/dpi`, `src/detection` | categories, noisy-OR, custom detector trait, event gating/fingerprints |
| Rules | `src/rules` | priority, allow override, CIDR/SNI/direction, auto-block, monitor |
| Engine/API | `src/engine`, `src/api` | multi-packet flows, bypass, auth, CSP, mode switching |
| CLI/API E2E | `tests/cli.rs` | inspect pcap/pcapng, config round-trip, live API-only daemon, dashboard, token, status/rules CLI, hot reload, SIGTERM |
| Flow E2E | `tests/flows.rs` | SYN+out-of-order TCP reassembly, SNI rule drop, reverse-direction verdict, benign TLS no-block |
| Quality | `tests/detection_quality.rs` | precision/recall on labelled fixtures |
| Dashboard static | `tests/web-ui.cjs` | required elements, endpoints, token header, CSP/no external assets |
| Privileged | `tests/live_capture.rs`, `tests/enforcement.rs` | real capture and actual NFQUEUE allow/drop |

## Fixtures

Generated reproducibly with:

```bash
python3 scripts/make-fixtures.py
```

| Fixture | Label | Expected |
|---|---|---|
| `benign_tls.pcap` / `.pcapng` | benign | TLS + SNI, no security event |
| `benign_http.pcap` | benign | HTTP/1, no security event |
| `benign_dns.pcap` | benign | DNS query, no security event |
| `ipv4_fragmented_dns.pcap` | benign | out-of-order fragments reassemble to DNS |
| `proxy_socks5.pcap` | proxy | SOCKS5 request, 0.97, auto-block decision |
| `proxy_http_connect.pcap` | proxy | CONNECT, 0.97 |
| `proxy_vless_plaintext.pcap` | proxy | VLESS request, 0.95 |
| `proxy_trojan_plaintext.pcap` | proxy | Trojan request, 0.97 |

The quality test reports:

```text
synthetic fixtures: TP=4 FP=0 TN=4 FN=0 precision=1.000 recall=1.000
```

This is a regression set, not a representative Internet corpus. It contains no
encrypted VLESS/Trojan/VMess/REALITY positives because those are not observable
without keys. A real-world evaluation needs a labelled, privacy-reviewed capture
corpus; no such accuracy is claimed here.

## Benchmarks

```bash
cargo bench --bench packet
cargo bench --bench reassembly
```

Criterion writes HTML reports under `target/criterion/`. Benchmarks measure
CPU-only parser/classifier/reassembly/rule costs, not line rate.

Measured on Linux 6.8 x86_64, Rust 1.99.1, release benchmark profile,
`--quick` short samples:

| Benchmark | Time |
|---|---:|
| `parse_ethernet_ipv4_tcp_tls` | 28.2 ns |
| `tls_client_hello` | 2.11 µs |
| `http_request` | 380 ns |
| `socks5_request` | 106 ns |
| `dns_query` | 176 ns |
| `engine_packet_existing_flow` | 289 ns |
| `tcp_reassembly_in_order_64x1460` | 3.15 µs |
| `tcp_reassembly_out_of_order_64x1460` | 13.0 µs |
| `rules_10_priority_match` | 140 ns |

Derived single-core estimate for the synthetic existing-flow benchmark:
`1 / 289 ns ≈ 3.46 Mpps`; at 1500-byte frames the arithmetic upper bound
(3.46M × 12,000 bits) is ~41.5 Gbps, excluding NIC, kernel capture, NFQUEUE,
locking contention and analysis mix. It is included to make the measurement
interpretable, not as a claimed end-to-end rate. Quick-mode samples vary with
CPU frequency and host load; rerun for publication numbers.

TLS ClientHello parsing is slower than the other parsers because it builds
metadata vectors and computes an MD5 JA3-style fingerprint. It runs only for new
TLS flows, not every packet.

A separate offline replay measurement used a generated 50,000-record pcap with
49,999 distinct TLS flows (each flow forces classification and persistent flow
state), `max_flows = 100000`:

```text
/usr/bin/time -v axion inspect --pcap /tmp/axion-replay.pcap --json
records: 50000  active_flows: 49999  parse_errors: 0
Elapsed: 0:00.86  User: 0.72s  System: 0.13s  Maximum resident set: 299776 KiB
```

That is ~58.1k packets/s single-core for a worst-case new-flow TLS replay and
~6.0 KiB peak RSS per live flow (including process baseline) in this build;
user+system CPU was 0.85s over 0.86s wall (~one core busy). It is an offline
file-processing measurement, not NIC/NFQUEUE throughput. Real flow mix and
stream reassembly change memory use; budget for `max_flows` accordingly.

## Reporting

When publishing results, include:

- hardware, NIC, kernel, MTU, packet size mix;
- build flags and Rust version;
- rules/detector configuration and capture backend;
- pcap or generator and labelled ground truth;
- pps/Gbps/latency/CPU/RSS and error/drop counters;
- precision/recall definition (flow-level vs event-level).

Do not compare the synthetic benchmarks above with hardware line-rate claims.
