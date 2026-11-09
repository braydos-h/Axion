# Live Demos

Axion's Live Demo mode is an isolated, deterministic packet replay laboratory.
It exists so that anyone can clone the repository, run one command, open the
dashboard and watch the real Axion pipeline classify example traffic without
root, capture privileges, NFQUEUE, firewall changes or external network access.

Nothing in the demo pipeline is a mock classifier. Each session owns a private
`Engine` and replays committed pcap/pcapng fixtures through the same
`PcapReader`, packet parsers, flow table, TCP reassembler, DPI classifier,
detection scoring and rule engine used by live capture and offline inspection.
The dashboard reports counters, rate samples, flows, evidence, confidence and
rule decisions from that engine.

## Quick start

```bash
cargo build --release
./target/release/axion demo
```

Then open <http://127.0.0.1:8787/> and choose a scenario. Useful flags:

```bash
axion demo --bind 127.0.0.1:9000
axion demo --max-sessions 2
./target/release/axion --config config/axion.demo.example.toml demo
```

`Ctrl-C` closes the server and releases all sessions.

The command:

1. Forces a fresh monitor-only runtime with capture disabled.
2. Starts the embedded dashboard and demo API on the selected address.
3. Embeds the deterministic fixtures in the binary; no files are read from a
   request and no download is required.
4. Serves the Live Demos view alongside the normal dashboard.
5. Never opens a raw socket, NFQUEUE handle, nftables rule or external
   connection.

No root or capability is required. Offline replay and demo mode are ordinary
userspace work.

## Scenarios

The scenario registry is compiled into the binary in `src/demo/mod.rs`. Fixture
bytes come from `tests/fixtures/` through `include_bytes!`.

| ID | Demo | Fixtures | Key output |
|---|---|---|---|
| `normal-https` | Normal HTTPS Traffic | `benign_tls.pcapng` | TLS 1.3, SNI `www.example.com`, ALPN `h2`/`http/1.1`, cipher/extension counts, JA3, allow verdict |
| `socks5-proxy` | SOCKS5 Proxy Detection | `proxy_socks5.pcap` | SOCKS5 request, target `example.com:443`, 0.97 proxy confidence, auto-block rule decision |
| `http-connect` | HTTP CONNECT Detection | `proxy_http_connect.pcap` | CONNECT target, HTTP metadata, 0.97 proxy confidence, drop decision |
| `vless-trojan` | VLESS and Trojan Detection | `proxy_vless_plaintext.pcap`, `proxy_trojan_plaintext.pcap` | `xray-vless` and `trojan-plaintext` findings with target metadata |
| `dns-http` | DNS and HTTP Inspection | `benign_dns.pcap`, `benign_http.pcap` | DNS question/type, HTTP method/host/target and monitor-rule events |
| `traffic-enforcement` | Traffic Enforcement | TLS, DNS, HTTP, SOCKS5, CONNECT fixtures | Explicit allow/monitor/log/drop rule evaluation; drops are simulated |
| `mixed-traffic` | Mixed Traffic Simulation | All fixture families | Interleaved timeline, live charts, protocol distribution, flows and events |

The enforcement scenario uses a small demo policy:

- `allow-trusted-https` — explicit ALLOW for the TLS fixture.
- `monitor-dns-queries` — MONITOR rule for DNS classification.
- `log-http-requests` — LOG rule for cleartext HTTP on port 80.
- `drop-plaintext-proxies` — DROP rule for direct `proxy` category findings.

The rule engine reports the real matched rule and real action. Because the
engine is constructed with `can_enforce = false` and monitor mode, `blocked` is
always false and the dashboard labels drop/reject verdicts **simulated**. No
packet is discarded by a demo.

## Architecture

```text
embedded pcap/pcapng fixtures
          │
          ▼
PcapReader (classic + pcapng)
          │
          ▼
DemoManager ticker (50 ms)
          │  bounded frames, scenario order, playback speed
          ▼
private Engine per session
  packet parser → fragment cache → flow table → TCP reassembly
      → DPI classifier → confidence/evidence → rule engine
          │
          ▼
bounded Telemetry (event ring, 250 ms rate samples, history)
          │
          ▼
GET /api/demo/sessions/{id} (dashboard polls ~650 ms)
          │
          ▼
charts, protocols, flows, events, controls
```

### Playback lifecycle

- **Start** creates a session with a private engine and a parsed frame list.
- **Playing** advances frames on a fixed schedule derived from the scenario's
  base step and the requested speed. A short lead-in makes the first chart
  samples visible; a short completion hold keeps the final state readable.
- **Pause** stops advancing. Counters and flow state are retained.
- **Resume** continues from the next frame.
- **Reset** replaces the engine and frame cursor, preserving the session id and
  speed. All counters start from zero.
- **Stop** removes the session and releases its engine.
- **Speed** is clamped to `0.25–8.0×`.
- **Completion** occurs after the last frame and hold period, but the session
  remains readable until stopped or expired.

Sessions are advanced by one manager ticker, not one task per session. This
keeps scheduling and CPU bounded. The manager caps concurrent sessions (default
4 in `axion demo`, hard maximum 8), bounds each fixture list to 2048 frames,
allows at most 32 catch-up steps per tick, and expires inactive sessions after
30 minutes. When the session limit is reached, the manager may evict an inactive
paused or completed session to make room for a new playback. Telemetry is
bounded by the same event/history limits used in production.

Reproducibility: fixture order, parser input, classification findings, evidence,
confidence and rule evaluation are deterministic. Playback pacing, sampled
rates and wall-clock duration are real measurements of the local run and
therefore vary with scheduler load, speed and machine performance. The dashboard
does not present them as a benchmark.

### Polling vs. SSE

The existing dashboard already polls `/api/status`, `/api/events` and
`/api/flows`. Demo mode follows that architecture: the UI polls a session detail
endpoint every 650 ms and the bounded session list every 2.8 s. No SSE or
WebSocket dependency is added. The backend ticker (50 ms) and UI polling are
independent; a slow browser cannot slow packet processing.

## API

All routes are under the existing authentication middleware, request body limit
and security headers. A configured token is required for every `/api/demo/*`
route exactly like the rest of the API. `/api/health` remains unauthenticated.

```text
GET    /api/demo/scenarios
GET    /api/demo/status
GET    /api/demo/sessions
POST   /api/demo/sessions                       {"scenario_id":"mixed-traffic","speed":1.0}
GET    /api/demo/sessions/{id}
GET    /api/demo/sessions/{id}/status
GET    /api/demo/sessions/{id}/flows?limit=N
GET    /api/demo/sessions/{id}/events?limit=N
POST   /api/demo/sessions/{id}/pause
POST   /api/demo/sessions/{id}/resume
POST   /api/demo/sessions/{id}/reset
POST   /api/demo/sessions/{id}/speed            {"speed":2.0}
DELETE /api/demo/sessions/{id}
POST   /api/demo/sessions/{id}/stop
DELETE /api/demo/sessions/{id}/stop
```

Example:

```bash
curl -s http://127.0.0.1:8787/api/demo/scenarios | jq '.scenarios[].id'
curl -s -X POST -H 'content-type: application/json' \
  -d '{"scenario_id":"socks5-proxy","speed":1.0}' \
  http://127.0.0.1:8787/api/demo/sessions | jq
```

Response fields include the state, speed, frame progress, real packet/byte
counters, bounded rate history, protocol counts, flow snapshots, detection
events, matched rules, simulated-drop count and an explicit isolation block:

```json
{
  "fixture_replay": true,
  "real_capture": false,
  "real_enforcement": false,
  "external_network": false,
  "accepts_paths": false,
  "accepts_uploads": false
}
```

Unknown scenario IDs, speed values outside the range, pause/resume in the wrong
state and expired sessions produce bounded JSON errors (404/400/409/429). No
request field is ever interpreted as a filesystem path or executable.

## Security boundaries

Demo mode is designed for a public, read-only showcase of analysis output. It is
deliberately separated from production capture and enforcement:

- **No capture:** no AF_PACKET socket, libpcap handle or pcap path from a
  request. Fixtures are embedded and selected by a static scenario ID only.
- **No enforcement:** `Engine` is constructed with `can_enforce = false`, mode
  is monitor, and no NFQUEUE code runs. `axion demo` does not call nftables or
  change any firewall rule.
- **No arbitrary input:** there is no upload endpoint, no path parameter used
  by the demo backend, and no external command execution. Request bodies contain
  only a whitelisted scenario ID and a numeric speed.
- **Isolation:** every session has its own engine, rule store, telemetry, flow
  table and fragment cache. Demo traffic never enters the production engine.
- **Demo-only guard:** when started by `axion demo`, `POST /api/mode`,
  `POST /api/dry-run` and `POST /api/rules/reload` return `403`. The rules and
  policy exposed by `/api/rules` are a sanitised demo server configuration, not
  the host's production capture policy.
- **Bounded resources:** session limit, frame limit, per-tick step limit, event
  capacity, rate history, session TTL, speed bounds and the existing request
  body limit.
- **Preserved security controls:** bearer-token authentication, constant-time
  token comparison, CSP, `X-Frame-Options: DENY`, `nosniff`, referrer policy,
  permissions policy, no CORS and no external assets.
- **Honest output:** no decrypted TLS/REALITY/VMess claims. The VLESS/Trojan
  scenarios use plaintext headers that are genuinely observable. Encrypted
  payloads are not represented as readable.

Visitor controls are state-changing, but only for isolated demo sessions. That
is why a public instance can remain tokenless if desired: selecting a scenario,
pausing it, or resetting it cannot affect production traffic. Session IDs,
progress and results are visible to every visitor of the same demo server and
contain only fixture-derived data. If you need to restrict visitors, configure
`api.token` / `--token` and share it only with the intended audience.

## Public hosting

Do not expose a normal `axion start` management API publicly. Host the
demo-only runtime instead.

1. Build and run the demo on loopback:

```bash
cargo build --release
./target/release/axion --config config/axion.demo.example.toml demo --bind 127.0.0.1:8787
```

2. Put a TLS reverse proxy in front of it. Caddy example:

```caddyfile
demo.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8787
}
```

3. Add a visitor rate limit and request cap at the proxy. nginx example:

```nginx
limit_req_zone $binary_remote_addr zone=axion_demo:10m rate=30r/m;

server {
    listen 443 ssl http2;
    server_name demo.example.com;
    # ... TLS configuration ...

    location / {
        limit_req zone=axion_demo burst=20 nodelay;
        proxy_pass http://127.0.0.1:8787;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

4. Keep `/api/health` available for liveness checks. Do not cache
   `/api/demo/sessions/*`: responses change with playback.
5. Monitor process memory and the number of active sessions. The server itself
   bounds both, but a reverse proxy rate limit prevents trivial session churn.

If you bind `0.0.0.0` directly, the demo is still production-isolated, but you
lose TLS and proxy rate limiting. `config/axion.demo.example.toml` documents the
recommended loopback setup.

No public hosted instance is maintained by this repository. Do not add a demo
link to a deployment unless that URL genuinely exists and is operated by you.

## What each demo does not prove

- TLS-wrapped VLESS/Trojan/VMess, REALITY, XTLS and Shadowsocks are not
  decrypted. The TLS scenario intentionally demonstrates benign encrypted
  traffic; it is not a proxy detection.
- The weak REALITY/XTLS-style findings on the benign TLS fixture remain below
  the monitor threshold and cannot auto-block. They are metadata, not proof.
- A plaintext SOCKS5/CONNECT/VLESS/Trojan fixture is a deterministic parser
  test, not a statement about Internet-wide prevalence or precision.
- Rate and packet counts are measurements of replay pacing, not production
  throughput benchmarks.
- `DROP`/`REJECT` in the demo are policy verdicts only. Real enforcement is
  available only through the inline NFQUEUE backend on Linux.

## Tests

- `src/demo/mod.rs` unit tests cover the scenario registry, embedded fixture
  parsing, engine isolation, TLS/SOCKS5/VLESS/Trojan/DNS/HTTP classifier output,
  mixed interleaving, pause/resume/reset/speed behavior, session limits, stop,
  invalid IDs and speed bounds.
- `src/api/mod.rs` tests cover scenario listing, session creation, pause,
  resume, reset, stop, flows/events retrieval, authentication, session limits,
  unknown IDs and the demo-only management guard.
- `tests/web-ui.cjs` checks every demo dashboard element, API wiring, safety
  text, CSP/security headers, absence of inline scripts/external assets and the
  request body limit.
- `cargo test --locked`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo fmt --all -- --check`, `node tests/web-ui.cjs` and
  `cargo build --release --locked` are the release checks.

## Troubleshooting

- **Address already in use:** choose another `--bind` value.
- **Dashboard asks for a token:** a token is configured in the API config or
  `AXION_DEMO_TOKEN` / `AXION_API_TOKEN`. Enter it in the dashboard or unset it.
- **Demo controls return 403 for mode/dry-run/reload:** expected in demo-only
  mode. Those are production operations, not demo operations.
- **No events for benign TLS:** expected. TLS is an encrypted application
  protocol, not a proxy finding, and default policy does not log it.
- **A scenario completes quickly:** some fixtures contain one packet. Completion
  is real; reset or start another session. The final flow/event data remains
  inspectable until stop or TTL expiry.
