# Security model and hardening

## Threat model

Axion consumes hostile packet data and exposes an optional local management API.
It does not execute captured payloads, resolve names, or fetch external data.
The main risks are parser memory safety/DoS, accidental traffic black-holing,
and unauthorized policy changes.

## Parser and memory safety

- Input sizes are bounded at every layer (packet, fragment cache, reassembly
  cap, parser caps, DNS/TLS/HTTP/DNS/quic frame counts).
- Parsers use slice indexing only after explicit length checks. IPv4 IHL/total
  length, IPv6 extension lengths, TCP data offset, UDP length, TLS handshake
  sizes, DNS pointers, HTTP header lengths and pcap record lengths are all
  validated.
- No unsafe code is used in parsers/classifier/rules. Unsafe is confined to OS
  FFI (AF_PACKET, libpcap dynamic loading, NFQUEUE netlink, `/proc` clock ticks)
  with documented pointer/lifetime invariants.
- Fragment overlap conflicts discard the whole set; queued out-of-order TCP data
  is capped; parser loops have iteration limits.
- Flow/event/rate/fragment/capture queues are bounded and evict or drop with
  counters rather than growing without limit.
- The QUIC Initial decoder uses only public RFC 9001 keys and authenticated
  AES-GCM; authentication failure simply yields metadata-only classification.

## Privilege model

- Passive capture needs `CAP_NET_RAW` only.
- Inline NFQUEUE needs `CAP_NET_ADMIN` (or root). This is a high-impact
  capability; use a dedicated service user plus systemd ambient capabilities.
- The management API defaults to loopback and can require a bearer token;
  non-loopback without a token is rejected unless explicitly overridden.
- The dashboard/static assets contain no secrets or live data. `/api/*` data and
  mutations are token-protected when configured.
- Do not expose the API directly to the Internet; use SSH tunneling or an
  authenticated reverse proxy with TLS. Axion's own HTTP server is plaintext.
- Tokens are read from config/env and are not included in API status or logs.
  The dashboard keeps tokens in `sessionStorage`, not local storage.

## Enforcement safety

- Passive capture cannot enforce; status/dashboard make this explicit.
- `mode = "enforce"` requires an NFQUEUE backend; Axion refuses to start if it
  cannot bind the queue.
- `dry_run` and monitor mode always accept while recording would-be decisions.
- The kernel fail-open flag and nftables `bypass` are distinct; both are
  documented in [DEPLOYMENT.md](DEPLOYMENT.md).
- Management/loopback bypasses exist in policy and example nftables rules.
  Operators must still avoid queueing their own SSH/API path.
- `reject` maps to DROP for NFQUEUE; no forged RST packets are emitted by Axion.
- A broken verdict loop is visible through `enforcement_errors` and backend
  status; the kernel/nftables fail mode governs traffic.

## Management API hardening

- Loopback default; token comparison is constant-time for equal-length inputs.
- Request body limit (`api.request_body_limit`), no CORS headers, strict JSON
  content type for mutations.
- CSP (no inline scripts), `X-Frame-Options: DENY`, `nosniff`,
  `Referrer-Policy: no-referrer`, restrictive Permissions-Policy.
- Rule reload validates the full config and compiles CIDRs/rules before an
  atomic swap; invalid files leave the previous policy in place.
- No remote rule editing endpoint; the dashboard views and triggers reload of the
  operator-managed file.
- Live Demo endpoints accept only a static scenario ID and numeric speed. They
  never accept paths or uploads, use no external commands, and create private
  monitor-only engines. `axion demo` additionally rejects `/api/mode`,
  `/api/dry-run` and `/api/rules/reload`. See [DEMOS.md](DEMOS.md).

## Detection limits as security boundaries

Do not treat heuristic labels as cryptographic identification:

- VLESS/Trojan/VMess/REALITY/XTLS inside TLS are opaque.
- `vmess-suspected`, `reality-suspected`, `xtls-suspected` and
  WebSocket/gRPC transport scores can have false positives and never auto-block.
- Only structurally decoded plaintext proxy handshakes enter the auto-block
  category by default.
- ECH/DoH/DoT hide names; QUIC beyond Initial is encrypted.

## Logging and privacy

- Detection events include endpoints, ports, SNI/DNS names, evidence and rule
  decision. Event history is in memory only unless the operator exports the API.
- CLI/API access logs are minimal; Axion does not ship captured payloads to the
  API or dashboard.
- The dashboard displays flow/detection metadata, not payload bytes.

## Reporting vulnerabilities

Use the repository's GitHub Security Advisory feature rather than a public issue
for memory-safety or privilege-escalation reports. Include a reproducer pcap if
possible, the exact commit, configuration, kernel and privileges.

## Known hardening gaps

- No seccomp/landlock profile in the sample systemd unit; add one for your
  environment after validating needed syscalls (AF_PACKET/netlink).
- No TLS on the management API itself; terminate TLS in a local reverse proxy.
- The classification code is not formally verified; fuzzing harnesses are a
  useful contribution.
- NFQUEUE uses one verdict loop; sustained overload can increase latency and
  queue-full drop/accept behaviour depends on configured fail mode.
- Enforcement is per packet: early fragments/first payloads may be accepted
  before reassembly/classification completes. Strict fragment handling needs
  kernel-side defragmentation and explicit policy.
