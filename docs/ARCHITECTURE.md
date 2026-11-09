# Architecture

Axion is a single Rust binary plus a reusable library (`src/lib.rs`). The hot
packet path is synchronous; Tokio is used for the management API, signals and
periodic maintenance.

## Module map

```text
src/
├── main.rs                 CLI (start/status/rules/inspect/config)
├── lib.rs                  library surface
├── config/                 TOML schema, defaults, validation, env overrides
├── capture/
│   ├── mod.rs              FrameSource trait, bounded pipeline, buffer pool
│   ├── af_packet.rs        native AF_PACKET + recvmmsg batching
│   └── libpcap.rs          runtime-loaded libpcap backend
├── packet/
│   ├── mod.rs              PacketView/Fragment types, link dispatch, pcap link types
│   ├── ethernet.rs         Ethernet II + VLAN/QinQ
│   ├── ip.rs               IPv4/IPv6 + extension headers/fragments
│   ├── transport.rs        TCP/UDP/ICMP views and flags
│   ├── fragment.rs         bounded IPv4/IPv6 fragment reassembly
│   └── pcap.rs             streaming classic pcap and pcapng reader
├── flow/
│   ├── mod.rs              five-tuple flows, direction, metadata, GC
│   └── reassembly.rs       TCP stream reconstruction
├── protocols/              pure bounded parsers (TLS, HTTP, DNS, ...)
├── dpi/                    classifier, findings, scores, detector trait
├── detection/              event gating and fingerprints
├── rules/                  rule compilation, precedence, ArcSwap hot reload
├── engine/                 end-to-end packet pipeline and verdicts
├── firewall/
│   ├── mod.rs              inline loop and shutdown
│   └── nfqueue.rs          netlink NFQUEUE client (no C dependency)
├── telemetry/              atomics, rate ring, event ring, /proc stats
├── demo/                   isolated fixture replay, sessions, bounded ticker
└── api/                    axum API + embedded dashboard assets
```

## Packet flow

1. A `FrameSource` (AF_PACKET, libpcap, pcap replay, or NFQUEUE L3) yields a
   buffer. Live capture uses a bounded pool and channel.
2. Workers call `Engine::process_link_frame` or `process_l3_frame`. Parsing is
   zero-copy: `PacketView` borrows the capture buffer.
3. IP fragments go through a global bounded `FragmentCache`; a completed payload
   is parsed as transport data. Conflicting overlaps drop the set.
4. `FlowTable::get_or_create` canonicalises the word pair (lower endpoint first),
   stores the first-seen source as the client, and returns a per-flow lock.
5. `FlowState::observe` counts bytes/packets, records a packet-size histogram,
   tracks TCP flags, and feeds TCP payload bytes into the direction's
   `TcpReassembler`. UDP datagrams are bounded first-datagram samples.
6. Analysis runs only when there is new contiguous payload and the previous
   classification is incomplete or enough new bytes arrived. Handshake parsers
   therefore see a complete first flight without re-running for every packet.
7. `Classifier::analyze` runs built-in parsers and optional `ProtocolDetector`
   implementations, producing `Finding`s with categories/confidence/evidence.
8. The rule engine is evaluated with flow metadata, SNI/DNS, categories and
   scores. The decision is stored on the flow.
9. In monitor mode the verdict is recorded and every packet is accepted. In
   enforce mode with NFQUEUE, the verdict maps to `ACCEPT`/`DROP`; subsequent
   packets in a blocked flow are dropped too.

## Demo replay

`axion demo` runs the same binary in a separate demo-only configuration. The
`demo` module accepts only static scenario IDs, embeds pcap/pcapng fixtures with
`include_bytes!`, and creates a private monitor-only `Engine` per session. One
Tokio ticker advances all sessions at their configured speed; no raw sockets,
NFQUEUE handles, firewall calls or request-supplied filesystem paths are used.
The API exposes session detail through bounded polling endpoints. In demo-only
mode, production mutation routes (`/api/mode`, `/api/dry-run`,
`/api/rules/reload`) are rejected. See [DEMOS.md](DEMOS.md).

## Concurrency and ordering

- Live capture has one bounded MPMC channel and N worker threads. Packet order
  is preserved per worker but not globally; flows are protected by per-flow
  mutexes, so out-of-order arrival is tolerated by TCP reassembly.
- The flow map is a sharded `DashMap<FlowKey, Arc<FlowEntry>>`; the expensive
  classifier runs while holding only that flow's mutex, not the map lock.
- NFQUEUE runs one ordered loop: receive a bounded batch, process each packet,
  then send all verdicts in one netlink datagram. This keeps verdict/packet
  ordering simple and avoids cross-thread packet handoff.
- The API reads snapshots; it never holds a flow lock while doing network I/O.
- Rules are swapped with `ArcSwap`; packet processors take a cheap snapshot for
  each decision. Invalid reloads are rejected before the swap.

## Memory bounds

| Budget | Config |
|---|---|
| Flow entries | `general.max_flows` (oldest-idle eviction) |
| TCP stream prefix per direction | `general.max_reassembly_bytes` |
| Pending out-of-order bytes per direction | same as reassembly cap |
| Fragment sets | `general.max_fragment_sets` |
| Fragment payload memory | `general.max_fragment_bytes` |
| Capture channel | `capture.queue_capacity` frames |
| Buffer pool | batch × workers × 2, clamped |
| Detection events | `general.event_capacity` |
| Rate history | `telemetry.history_seconds` / sampling interval |
| HTTP/DNS/TLS parser input | 64 KiB hard cap in the classifier |

A capture queue overflow drops frames and increments `capture_drops`; it never
grows unbounded. Flow eviction and fragment expiry run on the telemetry
maintenance tick. Idle flows use `general.flow_idle_timeout_seconds`; flows with
a TCP reset or FINs from both directions are collected after a short 2-second
grace period.

## Safety and hostile input

- Every parser checks lengths before indexing; no parser trusts IPv4 total
  length, IPv6 payload length, TCP data offset, UDP length, TLS handshake length,
  HTTP header length, DNS compression pointers or pcap record lengths.
- Truncated packets are retained only to the captured bytes and marked; header
  truncation is a parse error.
- DNS compression pointers are jump-limited; TLS/QUIC frame loops are count- and
  byte-limited.
- Fragment offset + length is capped at 65535; duplicate/overlapping conflicting
  fragments discard the set.
- TCP reassembly normalises sequence numbers against the first payload/SYN,
  trims retransmissions, queues gaps, and stops at the byte cap.
- `unsafe` is limited to OS FFI in `capture/af_packet.rs`, `capture/libpcap.rs`,
  `firewall/nfqueue.rs` and `/proc` clock ticks. Each block documents the
  pointer/lifetime invariant.
- Parser panics would fail the process; tests exercise truncation and malformed
  paths, but this is not a formal proof.

## Extensibility

Built-in classifiers are ordinary Rust modules. Library users can implement
`dpi::ProtocolDetector` and register it with `dpi::Classifier`, then construct an
engine with `Engine::new_with_classifier`. This is a compile-time trait, not a
dynamic plugin system. Detectors return findings/evidence; scoring, event gating
and policy remain centralised.

## Deliberate non-goals

- No Xray/REALITY code, binaries, configs or subprocesses.
- No claim to decrypt ordinary TLS, ECH, IPsec, WireGuard, Shadowsocks, or
  post-Initial QUIC.
- No predefined “block all proxies” magic rule: direct plaintext proxy evidence
  can auto-block, while mimicry categories require explicit operator policy.
