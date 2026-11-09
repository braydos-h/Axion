# Rule and configuration reference

Axion configuration is TOML. Unknown keys are rejected. `axion config example`
prints the full sample; `axion config check` and `axion rules validate` validate
without starting capture.

## Top-level

```toml
[general]
mode = "monitor"              # monitor | enforce
dry_run = false
worker_threads = 0            # 0 = CPUs clamped to 8
max_flows = 100000
flow_idle_timeout_seconds = 120
fragment_timeout_seconds = 30
max_fragment_sets = 4096
max_fragment_bytes = 16777216
max_reassembly_bytes = 262144
event_capacity = 4096
auto_block_confidence = 0.92
monitor_confidence = 0.50
log_level = "info"

[capture]
backend = "auto"              # auto | af_packet | libpcap | none
interface = "eth0"
# pcap_file = "sample.pcap"   # start replays; inspect uses --pcap
snaplen = 2048
buffer_bytes = 8388608
batch_size = 64
queue_capacity = 2048
promiscuous = true
include_outgoing = true

[api]
enabled = true
bind = "127.0.0.1:8787"
# token = "change-me"         # AXION_API_TOKEN overrides
allow_insecure_remote = false
request_body_limit = 65536

[telemetry]
sample_interval_ms = 1000
history_seconds = 120
log_detections = true

[firewall]
queue_num = 0
queue_max_len = 1024
batch_size = 64
fail_open = true
bypass_tcp_ports = [22, 8787]
bypass_cidrs = ["127.0.0.0/8", "::1/128"]
reject_emulation = "drop"

[detection]
enabled = true
enable_quic_initial = true
enable_tls_fingerprint = true
enable_heuristics = true

[policy]
default_action = "allow"
allow_overrides = true
allowlist_cidrs = ["10.0.0.0/8"]
blocklist_cidrs = []
```

Notes:

- `general.auto_block_confidence` controls the built-in proxy block. Set it to
  `1.0` to disable automatic blocking (a score of exactly 1.0 remains possible,
  so explicit rules are the safer way to opt into blocking).
- `detection.enabled = false` disables automatic monitoring events and the
  built-in proxy auto-block. Explicit rules still run and can log/block.
- `firewall.fail_open` is mirrored to `NFQA_CFG_F_FAIL_OPEN`. nftables `bypass`
  is separate; see [DEPLOYMENT.md](DEPLOYMENT.md).
- `capture.backend = "none"` is useful for API-only smoke tests. It cannot
  enforce unless started with `--inline` (NFQUEUE does not use the capture
  backend).
- `mode = "enforce"` with `pcap_file` is rejected; offline analysis is always
  monitor-only.

## Actions

| Action | Meaning |
|---|---|
| `allow` | Accept and stop evaluating. Under `allow_overrides`, allow rules run first. |
| `monitor` | Record/emit a detection event, accept the packet. |
| `log` | Record/emit an event, accept; useful for audit rules. |
| `drop` | Drop the packet in enforce mode; record in monitor/dry-run. |
| `reject` | Same as drop for the NFQUEUE backend; use nftables reject if needed. |

None of these block in passive monitor mode. `dry_run` forces accept while
preserving would-be decisions and events.

## Rule schema

```toml
[[rules]]
name = "block-plaintext-proxies"     # required, unique
description = "optional text"
enabled = true
priority = 500                       # higher runs first
action = "drop"
log = true                           # emit a rule event

[rules.match]
src_cidrs = ["192.0.2.0/24"]
dst_cidrs = ["198.51.100.0/24", "2001:db8::/32"]
ports = [443, 8443]                  # matches either source or destination port
src_ports = [50000]
transports = ["tcp"]                 # tcp | udp | icmp | icmpv6
protocols = ["socks5", "http-connect", "xray-vless", "trojan-plaintext"]
categories = ["proxy"]
sni = ["*.blocked.example", "exact.example"]
dns = ["*.tracker.example"]
direction = "either"                 # either | client_to_server | server_to_client
min_confidence = 0.9
# max_confidence = 1.0
# min_bytes = 1024
# min_duration_ms = 5000
```

All match clauses are ANDed. Within a list, values are ORed. Empty/omitted
clauses match anything. `ports` checks both endpoints; combine `direction` and
`src_ports` for finer control.

Protocol labels currently include:

```text
tls, tls-in-connect, http1, http2, websocket, websocket-transport, grpc,
grpc-transport, dns, quic, socks4, socks5, socks5-udp, http-connect,
xray-vless, trojan-plaintext, vmess-suspected, reality-suspected,
xtls-suspected
```

Categories: `proxy`, `proxy_transport`, `obfuscation`, `encrypted`, `http`,
`dns`. Category matching only requires a positive category score; use
`min_confidence` for the strongest finding and/or explicit protocol labels for
precision.

SNI patterns are matched against the TLS/QUIC ClientHello SNI. DNS patterns are
matched against DNS question/answer names. A missing SNI/DNS name fails the
respective clause. Globs support `*` and `?`, case-insensitive.

## Precedence

1. Global `policy.allowlist_cidrs` (if either endpoint matches) → ALLOW.
2. Global `policy.blocklist_cidrs` → DROP.
3. If `allow_overrides = true`: ALLOW rules by descending priority, then all
   other rules by descending priority. First match wins.
4. If `allow_overrides = false`: all enabled rules by descending priority.
5. Built-in automatic policy (if `detection.enabled`):
   - `proxy_score >= general.auto_block_confidence` → DROP
     (`builtin:auto-block-proxy`),
   - otherwise strongest security score
     `>= general.monitor_confidence` → MONITOR
     (`builtin:monitor-suspicion`).
6. `policy.default_action`.

Equal priorities preserve file order. A failed reload leaves prior config loaded.
In enforce mode a blocked flow stays blocked for reverse-direction packets even
if the matching rule is direction-scoped; an explicit ALLOW rule/global
allowlist or a successful policy reload can clear it.

## Examples

Allow a partner before any block rule:

```toml
[[rules]]
name = "allow-partner"
priority = 1
action = "allow"

[rules.match]
sni = ["*.partner.example"]
```

Block plaintext VLESS/Trojan on non-standard ports:

```toml
[[rules]]
name = "block-vless-trojan"
priority = 200
action = "drop"
log = true

[rules.match]
protocols = ["xray-vless", "trojan-plaintext"]
transports = ["tcp"]
min_confidence = 0.9
```

Monitor login/QUIC metadata above 0.8 without blocking:

```toml
[[rules]]
name = "monitor-quic"
priority = 20
action = "monitor"

[rules.match]
protocols = ["quic"]
min_confidence = 0.8
```

Match a weak REALITY hypothesis only in a lab:

```toml
[[rules]]
name = "lab-reality-monitor"
priority = 10
action = "monitor"

[rules.match]
protocols = ["reality-suspected"]
min_confidence = 0.2
```

## Reload

- `SIGHUP` or `POST /api/rules/reload` re-reads the same config path.
- Validation/compilation errors return HTTP 400 and leave the old `Rules`
  ArcSwap value untouched.
- Reload covers `[[rules]]`, `[policy]`, `detection.enabled`,
  `general.auto_block_confidence` and `general.monitor_confidence`. Runtime mode
  switching is `POST /api/mode`; capture/API/telemetry changes require a restart.
- `axion rules validate` performs the same compile without a daemon.
