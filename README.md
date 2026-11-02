# Axion

Axion is a passive Rust network traffic intelligence tool. It groups observed TCP and UDP packets into bidirectional flows, extracts visible TLS ClientHello metadata, and uses conservative local heuristics to flag sustained traffic for review. An optional Cloudflare Clef typed-decision request can give a separate model assessment of selected flows. The browser dashboard is served by the same executable.

**Detection only:** Axion captures copies of packets. It does not decrypt, inject, drop, block, reset or terminate traffic, or change firewall rules. A TLS fingerprint, address, port, or SNI is not proof of VLESS. REALITY is designed to resemble ordinary TLS; neither the local heuristic nor Clef can verify VLESS/REALITY from these metadata. Unknown is the default. No detection rate has been established. Model scores are model outputs, not measured probabilities of correctness.

The research target is the [VLESS + REALITY + XTLS Vision installer](https://github.com/braydos-h/vless-xtls-vision-installer), which configures Xray's RAW/TCP transport with configurable camouflage. These generic behavioral signals also occur in ordinary applications. Test against your own authorized traffic.

## Requirements and build

Linux is the primary target. Install a Rust toolchain with [rustup](https://rustup.rs/) and libpcap headers, for example:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libpcap-dev
cargo build --release
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Fedora users can install `gcc`, `pkgconf-pkg-config`, and `libpcap-devel`. Live capture requires suitable privileges. For testing you can run with `sudo`; alternatively use an administrator-managed capture capability such as `sudo setcap cap_net_raw,cap_net_admin=eip target/release/axion` and understand the security implications of granting capabilities to an executable. Rebuilding replaces the binary and may remove its capabilities. Offline PCAP and demo do not require capture privileges.

## Run

```bash
axion interfaces
sudo axion capture --interface eth0
sudo axion capture --interface eth0 --web-port 8080
axion replay --file capture.pcap
axion demo
```

When using the release build, substitute `target/release/axion` for `axion`. Open <http://127.0.0.1:8080>. Replay reads the capture as fast as processing allows and leaves the dashboard running when the file ends. Demo generates explicitly labelled simulated metadata and does not request AI analysis. Ctrl+C stops Axion. Dashboard pause only pauses display updates; it does not stop capture or affect traffic. Clear removes displayed rows locally. Interface selection is available when capture has stopped; restart `capture` with that interface to begin a new live capture.

The dashboard listens on loopback by default. Its API provides access to sensitive connection metadata and has no user authentication: keep it on loopback or use a separately secured access layer. For configuration, CLI flags can also be set via `AXION_WEB_HOST`, `AXION_WEB_PORT`, `AXION_MAX_FLOWS`, and `AXION_FLOW_TIMEOUT_SECONDS`. Run `axion --help` for options.

## Cloudflare Workers AI

Copy `.env.example` to `.env` and set `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`. The token needs permission to use Workers AI for the account. The default `AXION_AI_MODEL=clef-flash` can be changed to `clef`. Set `AXION_AI_ENABLED=false` to start with cloud analysis disabled and `AXION_AI_MAX_REQUESTS_PER_MINUTE` to control request rate (default 30). Missing credentials leave local analysis operational. The indicator is offline until a request succeeds; a configured account is not tested proactively. The dashboard can toggle AI while the process is running.

Axion uses Cloudflare's [Workers AI REST endpoint](https://developers.cloudflare.com/workers-ai/get-started/rest-api/) and [Clef typed questions](https://developers.cloudflare.com/workers-ai/models/clef-flash/). It sends only selected flow metadata, never raw payloads or the API token to the browser. By default the request omits source/destination IP addresses and hostnames; it includes destination port, aggregate traffic statistics, TLS metadata/fingerprint and handshake observations. Set `AXION_AI_SHARE_IDENTITY=true` only if you explicitly want to include IP addresses and observable SNI. These metadata can themselves be sensitive: consult Cloudflare's data policies before enabling cloud classification. No complete browsing history is sent as a batch, although separately submitted flows may still reveal behavioral information. Clef scores are displayed separately from local heuristic scores.

The bounded AI queue receives only locally suspicious flows, at most once per flow. It uses timeout, rate spacing, retries and backoff without waiting in the capture loop. A full queue increments the analysis-drop counter. Capture-event drops indicate that the flow worker could not keep up; libpcap/kernel drops may not be included in that counter. The number of tracked flows and inactivity timeout are configurable. `AXION_WEIGHT_DURATION`, `AXION_WEIGHT_BIDIRECTIONAL`, `AXION_WEIGHT_VOLUME`, `AXION_WEIGHT_PACKETS` and `AXION_SUSPICION_THRESHOLD` accept values from 0 to 1; changes require restart. Weights and thresholds are illustrative, not validated detection rates.

## Evaluation

Create a labelled set of traffic captures in a controlled environment with consent: include ordinary browsing, downloads, streaming and long-lived TLS connections, plus separate sessions using the reference installer and Xray client. Collect a PCAP on a test endpoint using a passive capture tool, e.g. `sudo tcpdump -i eth0 -s 0 -w test.pcap`; protect the capture because it can contain sensitive data. Record ground truth externally, including timestamps and endpoints; never label a flow as VLESS solely from Axion's output. Replay each file with `axion replay --file test.pcap` and compare the API/dashboard's flow results to labels. Split captures by session and environment, not individual packets, to avoid leakage between training/tuning and evaluation. Count true positives (labelled target flagged), false positives (benign flagged), and false negatives (target unflagged). Report precision = TP / (TP + FP), recall = TP / (TP + FN), and false-positive rate = FP / (FP + true negatives), with sample sizes and unknowns. Repeat across applications, networks, implementations, and capture conditions; reserve an untouched test set. Do not interpret an AI score as measured precision.

## Limitations and troubleshooting

- TLS metadata is visible only when captured and not concealed; ECH can hide SNI. TLS version here is the highest offered ClientHello version, not a negotiated result. No decryption is attempted. JA3 is computed from visible ClientHello fields; no JA4 claim is made.
- Bounded TCP reconstruction handles fragmentation, overlaps and some out-of-order segments when the initial sequence is captured. Midstream capture, gaps, very large handshakes, IP fragmentation, unsupported link types and malformed packets may prevent extraction. UDP flows have aggregate statistics; QUIC is not decrypted or positively identified.
- Sent/received means the first observed direction and its reverse, not necessarily local host ingress/egress; the same convention applies to the fields sent to Clef. Timestamps come from the capture. Expiration and bounded eviction may remove flow details from the API; the dashboard keeps its own bounded displayed history.
- If capture fails, check the interface name, permissions, and libpcap installation. Containers may need host networking and appropriate capabilities. Promiscuous mode is not enabled.
- If AI stays offline, check credentials, account permission, network connectivity, model name and Workers AI availability. Errors are logged without the API token. Local detection remains available.
- If the UI cannot connect, check the configured bind address and port. Never expose the unauthenticated dashboard to untrusted networks.

The deterministic replay fixture is generated in the capture test; run `cargo test replay_generated_pcap` to exercise it without a saved capture file.

