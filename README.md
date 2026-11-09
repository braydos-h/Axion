# Axion

Axion is a Rust-native deep packet inspection (DPI) and Linux traffic
enforcement engine. It parses packets itself, tracks bidirectional flows,
reassembles TCP streams, classifies protocols, extracts TLS/QUIC/HTTP metadata,
scores proxy-like behaviour, evaluates its own rule engine, and can accept or
drop packets inline through NFQUEUE.

It is **not** a wrapper around Xray-core, REALITY, Suricata, nDPI, or another
DPI application. The analysis, flow tracking, detection scoring, rule
evaluation, capture pipeline and NFQUEUE client are implemented in this
repository. Xray-core and REALITY were removed as submodules and are not build
or runtime dependencies.

> **Scope and honesty.** Encrypted traffic cannot be inspected without keys.
> Axion detects what is observable: plaintext proxy handshakes, TLS/QUIC
> ClientHello metadata, HTTP metadata, DNS names, packet/flow behaviour, and
> transport patterns. VLESS/Trojan/VMess/REALITY carried inside ordinary TLS are
> not decrypted. REALITY is specifically designed to look like normal TLS, so
> Axion only exposes low-confidence heuristics for it and never auto-blocks on
> those heuristics alone. See [docs/DETECTION.md](docs/DETECTION.md).

## What works

- Linux AF_PACKET live capture with `recvmmsg` batching and a bounded worker pool.
- Optional runtime-loaded libpcap backend (no libpcap headers or C build dependency).
- Classic pcap and pcapng replay for `axion inspect`.
- Ethernet/VLAN, IPv4, IPv6 extension headers, TCP, UDP, ICMP, IPv4/IPv6 fragments.
- Bounded, wrap-aware, out-of-order/retransmission-aware TCP reassembly.
- Sharded, memory-bounded flow table with idle garbage collection and per-flow metadata.
- Protocol parsers: TLS ClientHello/ServerHello (SNI, ALPN, versions, ciphers,
  extensions, groups, JA3-style fingerprint), HTTP/1.x, HTTP CONNECT,
  WebSocket handshake, HTTP/2 preface/frames/gRPC hint, DNS (UDP/TCP), SOCKS4/4a,
  SOCKS5 (TCP greeting/request and UDP), plaintext VLESS and Trojan, and QUIC
  Initial packet decryption with TLS ClientHello recovery.
- Proxy/obfuscation detection with categories, confidence scores and evidence.
- TOML policy with CIDR/port/transport/protocol/category/SNI/DNS/
  confidence/byte/duration/direction matching, priorities, allowlist overrides,
  automatic high-confidence blocking and low-confidence monitoring.
- Inline NFQUEUE enforcement with batched verdicts, fail-open kernel flag,
  dry-run mode, runtime monitor/enforce switching and management bypasses.
- Embedded dashboard at `127.0.0.1:8787` (no external assets), optional bearer
  token, CSP/security headers and a small management API.
- Hot rule reload via SIGHUP or `POST /api/rules/reload` with validation; invalid
  reloads keep the previous policy.
- Deterministic fixtures, unit/integration/quality tests, Criterion benchmarks,
  release builds for x86_64 and aarch64, checksums and tagged releases.

## Quick start

Requirements:

- Linux (AF_PACKET/NFQUEUE; x86_64 or aarch64).
- Rust 1.85+ and a C linker for building.
- `CAP_NET_RAW` for passive capture, `CAP_NET_ADMIN` for NFQUEUE and nftables.
- nftables for inline deployments.

```bash
git clone https://github.com/braydos-h/Axion.git
cd Axion
cargo build --release

# Root is simplest; alternatively grant only the needed capabilities:
sudo setcap cap_net_raw,cap_net_admin+eip target/release/axion
sudo mkdir -p /etc/axion
sudo cp config/axion.example.toml /etc/axion/axion.toml

# Passive monitoring (never blocks)
sudo target/release/axion start --interface eth0 --mode monitor

# Dashboard
xdg-open http://127.0.0.1:8787/    # or curl http://127.0.0.1:8787/api/status
```

Offline analysis works without privileges:

```bash
axion inspect --pcap tests/fixtures/benign_tls.pcap
axion inspect --pcap tests/fixtures/proxy_socks5.pcap --json
```

CLI commands:

```bash
axion start --interface eth0 --mode monitor
axion start --interface eth0 --mode enforce   # requires NFQUEUE rules
axion start --inline --mode monitor           # inline backend, accept-all until switched
axion status
axion status --json
axion rules list
axion rules reload
axion rules validate
axion inspect --pcap sample.pcap
axion config example
axion config check
```

`--config FILE` is global: `axion --config /etc/axion/axion.toml start ...`.

## Inline enforcement

NFQUEUE is the only enforcement backend. Passive AF_PACKET capture can never
block traffic, and Axion reports that clearly in status and the dashboard.

Set up a queue for the traffic you want to inspect (forward path example):

```bash
# fail-open: if no Axion listener is attached, nftables accepts the packet
sudo scripts/install-nfqueue.sh fail-open 0

# fail-closed variant (queued traffic is dropped if the listener disappears)
sudo scripts/install-nfqueue.sh fail-closed 0

sudo axion --config /etc/axion/axion.toml start --mode enforce
```

The script only adds a `forward` hook and bypasses SSH and the dashboard port by
default. Read [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) before enforcing on a
remote host. There are two distinct fail-open mechanisms:

- `firewall.fail_open = true` sets the kernel `NFQA_CFG_F_FAIL_OPEN` flag,
  which accepts packets when the queue is full.
- nftables `queue ... bypass` accepts packets when no userspace listener exists.

Both should be used together for a fail-open deployment. Axion fails startup if
it cannot bind the queue; it does not silently pretend to enforce. Runtime
NFQUEUE errors are logged and counted, and the kernel flag governs queue-full
behaviour. `REJECT` rules are enforced as DROP by the NFQUEUE backend; use an
nftables reject rule if you need TCP reset/ICMP unreachable semantics.

Runtime controls:

```bash
curl -X POST -H 'content-type: application/json' \
  -d '{"mode":"monitor"}' http://127.0.0.1:8787/api/mode
curl -X POST -H 'content-type: application/json' \
  -d '{"enabled":true}' http://127.0.0.1:8787/api/dry-run
```

If the API has `api.token`, add `-H 'X-Axion-Token: ...'`. The API binds to
loopback by default. A non-loopback bind without a token is rejected by
configuration validation unless explicitly overridden.

## Detection matrix

| Signal | What is actually visible | Typical confidence | Auto-block? |
|---|---|---:|---|
| SOCKS5 request | Full plaintext connect/associate request | 0.97 | Yes |
| SOCKS4/4a request | Full plaintext request | 0.95 | Yes |
| HTTP CONNECT | Full request line/headers | 0.97 | Yes |
| Plaintext VLESS | Version, UUID, command, target | 0.84–0.95 | Yes |
| Plaintext Trojan | 56-hex password hash + command + target | 0.97 | Yes |
| TLS | Client/ServerHello metadata, SNI, ALPN, fingerprint | 0.99 | No (encrypted app) |
| QUIC Initial | Header plus decrypted TLS ClientHello | 0.84–0.99 | No (encrypted app) |
| HTTP/1, HTTP/2, WebSocket, gRPC | Request/frame/handshake metadata | 0.80–0.99 | No by themselves |
| WebSocket transport | HTTP upgrade is visible; inner payload is not | 0.32 transport score | Only via explicit rule |
| gRPC transport | HTTP/2 + `application/grpc` hint | 0.30 transport score | Only via explicit rule |
| VMess | Opaque high-entropy stream heuristic only | 0.16–0.20 | No |
| REALITY | TLS mimics ordinary browsing; uTLS-like traits | 0.15–0.28 | No |
| XTLS | TLS 1.3 long-flow heuristic | 0.15 | No |
| TLS-wrapped VLESS/Trojan/VMess/Xray | Not decryptable | n/a | n/a |

The default auto-block threshold is `0.92` and only applies to the **proxy**
category (decoded handshakes). TLS mimicry, WebSocket/gRPC transports and opaque
streams live in separate categories and cannot auto-block. The monitor threshold
is `0.50`; weaker findings remain in per-flow metadata and can be matched by
explicit rules with any `min_confidence`.

Traffic categories are exposed to rules as `proxy`, `proxy_transport`,
`obfuscation`, `encrypted`, `http` and `dns`.

## Configuration

See [config/axion.example.toml](config/axion.example.toml),
[config/axion.inline.example.toml](config/axion.inline.example.toml) and
[docs/RULES.md](docs/RULES.md). Main sections:

```toml
[general]      # mode, thresholds, limits, timeouts, workers
[capture]      # backend, interface, snaplen, queue size, batching
[api]          # bind, token, request limit
[telemetry]    # sampling/event history
[firewall]     # queue number, max length, fail-open, bypasses
[detection]    # parser/heuristic toggles
[policy]       # default action, allow/block overrides
[[rules]]      # name, priority, action, match, log
```

Rule actions: `allow`, `drop`, `reject`, `log`, `monitor`. Matching supports:

- `src_cidrs`, `dst_cidrs`
- `ports` (either side), `src_ports`
- `transports` (`tcp`, `udp`, `icmp`, `icmpv6`)
- `protocols` (`tls`, `http1`, `http2`, `dns`, `quic`, `socks5`,
  `http-connect`, `websocket`, `grpc`, `xray-vless`, `trojan-plaintext`,
  `vmess-suspected`, `reality-suspected`, `xtls-suspected`, ...)
- `categories`
- `sni` and `dns` globs (`*`, `?`)
- `direction` (`either`, `client_to_server`, `server_to_client`)
- `min_confidence`, `max_confidence`, `min_bytes`, `min_duration_ms`

Higher priority wins. With `allow_overrides = true` (default), ALLOW rules are
evaluated before all other rules. Global allowlist CIDRs are a hard override;
global blocklist CIDRs are next. Invalid configuration or reloads are rejected
atomically and the prior policy stays active.

## Dashboard and API

The dashboard is embedded into the binary and served from the same listener.
It shows throughput/PPS history, active flows, protocol distribution, proxy
detections, blocked connections, events, rules, CPU/RSS, capture/enforcement
mode and dry-run state, and can toggle monitor/enforce, dry-run and rule reload.

API endpoints:

```text
GET  /api/health          unauthenticated liveness
GET  /api/status          mode, backend, metrics, counters, rate history
GET  /api/flows?limit=N   recent flow snapshots
GET  /api/events?limit=N  detection events
GET  /api/rules           compiled configuration view
POST /api/rules/reload    re-read config, validate and swap
POST /api/mode            {"mode":"monitor"|"enforce"}
POST /api/dry-run         {"enabled":true|false}
```

Security defaults: localhost bind, optional bearer token, JSON body limit, no
CORS, CSP, `X-Frame-Options: DENY`, `nosniff`, no external dashboard assets.
Static assets are public; all `/api/*` data endpoints require the token when one
is configured.

## Architecture

```text
AF_PACKET / libpcap / pcap file / NFQUEUE
        │
        ▼
safe parsers ──► IP fragment cache ──► L4 parser
        │
        ▼
bounded flow table ──► TCP reassembly ──► DPI classifier
                                              │
                                   protocol findings + scores
                                              │
                                              ▼
                                       rule engine
                                              │
                    ALLOW / LOG / MONITOR / DROP / REJECT
                                              │
                         passive: verdict recorded only
                         NFQUEUE: ACCEPT or DROP batched verdict
```

Hot-path packet processing uses synchronous worker threads, not Tokio. Tokio
serves the management API, signals and maintenance timers. Per-flow state is
behind a per-flow mutex; the flow map is a sharded DashMap. TCP payloads are
retained only up to `max_reassembly_bytes` (default 256 KiB) per flow; the
capture-to-worker queue and event/rate histories are bounded. Conflicting
fragment overlaps are discarded to avoid IDS/IPS overlap evasion.

More detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testing

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
node tests/web-ui.cjs
cargo bench --no-run --locked

# privileged, optional:
sudo -E cargo test --test live_capture -- --ignored --nocapture
sudo -E cargo test --test enforcement -- --ignored --nocapture
```

Fixtures are deterministic and generated by `scripts/make-fixtures.py`; they are
committed under `tests/fixtures/`. The quality test measures precision/recall on
the eight labelled fixtures. Synthetic fixtures are useful regression guards,
not evidence of Internet-wide accuracy.

### Measured locally

Environment: Linux 6.8 x86_64, Rust 1.99.1, release benchmark profile,
`cargo bench -- --quick` (short single-run samples). Re-run on your hardware.

| Benchmark | Time |
|---|---:|
| Ethernet+IPv4+TCP+TLS frame parse | 28.2 ns |
| TLS ClientHello parse (incl. JA3 MD5) | 2.11 µs |
| HTTP/1 request parse | 380 ns |
| SOCKS5 request parse | 106 ns |
| DNS query parse | 176 ns |
| Existing-flow engine packet processing (no capture I/O) | 289 ns |
| TCP reassembly, 64×1460 B in order | 3.15 µs |
| TCP reassembly, 64×1460 B out of order | 13.0 µs |
| 10-rule priority match | 140 ns |

The 289 ns pipeline figure corresponds to ~3.46 Mpps on one core in this
synthetic test; the arithmetic at 1500-byte frames is ~41.5 Gbps, but that is
**not** an end-to-end Gbps claim. Real
throughput depends on NIC, kernel, packet size, rule count, analysis mix and
enforcement mode. The repository includes no invented line-rate results.

Quality on the labelled fixtures: TP=4, FP=0, TN=4, FN=0, precision=1.000,
recall=1.000. This small set contains synthetic plaintext proxy and benign TLS/
HTTP/DNS/fragmented DNS captures only. REALITY/VMess/TLS-wrapped cases are not
claimed as detected.

## Limitations

- TLS 1.3 application data, VMess, Trojan/VLESS inside TLS, REALITY, XTLS,
  Shadowsocks and other encrypted tunnels are opaque without keys.
- Encrypted ClientHello (ECH), DNS-over-HTTPS and DNS-over-TLS hide names.
- QUIC Handshake/0-RTT/1-RTT packets are not decrypted; only Initial packets use
  public initial keys.
- HTTP/2 HPACK is not fully decoded; gRPC detection is a bounded literal hint.
- VMess detection is a weak entropy heuristic. It never auto-blocks.
- REALITY/XTLS heuristics have false positives (ordinary browsers can look
  similar) and never auto-block.
- NFQUEUE adds latency and must be sized/queued carefully; this build uses one
  verdict loop and does not implement AF_XDP/eBPF acceleration.
- Inline verdicts are per packet. A blocked flow drops subsequent packets, but
  the first payload packet(s) before classification may already be accepted.
  IP fragments are reassembled for analysis, yet earlier fragments may have been
  accepted; use conntrack/nftables defragmentation for strict fragment policy.
- Fragmented QUIC, IPv6 jumbograms, IPsec ESP and unsupported pcap link types are
  rejected/skipped rather than guessed.
- Rules hot-reload replaces policy/rule settings from the config file; capture,
  API bind and telemetry settings require a restart.
- The dashboard manages (views/reloads) rules; it does not edit TOML in place.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — modules, buffering, concurrency.
- [docs/DETECTION.md](docs/DETECTION.md) — each detector, evidence, scoring, limits.
- [docs/RULES.md](docs/RULES.md) — complete rule schema and precedence.
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) — capabilities, nftables, systemd, safety.
- [docs/TESTING.md](docs/TESTING.md) — fixtures, metrics, benchmark methodology.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model and hardening notes.

## License

GPL-3.0-only. See [LICENSE](LICENSE). Axion is an independent implementation;
the removed Xray-core/REALITY source trees are not part of this project.
