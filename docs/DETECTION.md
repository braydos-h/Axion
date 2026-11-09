# Detection methodology and limitations

Axion emits `Finding`s with a protocol name, category, confidence in `[0,1]`,
and human-readable evidence. Findings are deduplicated per protocol and category
scores combine with noisy-OR:

```text
score = 1 - Π(1 - confidence_i)
```

The rule engine matches individual protocol names, categories, and the maximum
finding confidence. Automatic blocking applies only to the `proxy` category and
only above `general.auto_block_confidence` (default 0.92). Weak categories
(`proxy_transport`, `obfuscation`) require explicit rules.

## TLS

**What is parsed**

- TLS record header and ClientHello/ServerHello handshake framing.
- Legacy version, random/session ID length, cipher suites, extensions.
- SNI with ASCII hostname validation.
- ALPN protocols.
- Supported groups, EC point formats, signature algorithms, supported versions.
- Key-share group IDs, ECH presence, GREASE count.
- JA3-style canonical string and its MD5 (this is the classic JA3 construction;
  GREASE values are included and the string is stored for transparency).

**Evidence:** handshake type, version, number of ciphers/extensions, SNI/ALPN.

**Limitations:** application data is encrypted. No plaintext protocol is inferred
inside TLS. ECH can hide SNI. A TLS ClientHello is normal traffic and is not a
proxy detection.

## QUIC Initial

Axion parses the QUIC long header and, for v1/v2 Initial packets, derives the
publicly specified Initial keys from the DCID (HKDF-SHA256), removes header
protection (AES-128), and decrypts the payload (AES-128-GCM). CRYPTO frames are
assembled and the TLS ClientHello is parsed for SNI/ALPN.

**Limitations:** only Initial keys are public. Handshake/0-RTT/1-RTT packets,
and any payload after the handshake, remain encrypted. Fragmented QUIC across
multiple datagrams is not reassembled. Version negotiation/unknown versions only
yield header metadata.

## HTTP/1.1, CONNECT, WebSocket

The parser recognises request/response lines, a bounded set of headers, Host,
User-Agent, content type, `Upgrade: websocket` + `Connection: upgrade`, and
`CONNECT target:port`. CONNECT is direct proxy evidence (0.97). WebSocket is an
application protocol and a common proxy transport; its handshake alone is not
evidence of a proxy, so it adds a 0.32 `proxy_transport` finding.

When a CONNECT tunnel contains a TLS ClientHello in the same direction, Axion
also extracts its SNI (`tls-in-connect`). The tunnel payload itself is not
decrypted.

**Limitations:** HTTP/2+ WebSocket extended CONNECT is not HPACK-decoded. Header
values may be truncated in capture; missing headers weaken but do not crash the
parser.

## HTTP/2 and gRPC

Axion recognises the HTTP/2 client preface and valid frame sequences, beginning
with SETTINGS for server-side captures. Frame types/counts are metadata.
gRPC is a bounded literal `application/grpc` hint in the header block; HPACK is
not fully decoded and Huffman-encoded values may not be visible. A gRPC finding
is application evidence plus a 0.30 `proxy_transport` hint, never a block on its
own.

## DNS

Parses UDP and DNS-over-TCP framed messages: header flags, questions, A/AAAA/
CNAME/NS/PTR answers. Compression pointers are loop- and jump-limited. On port
53/5353 the finding is 0.97; off-port structural matches are 0.62 and never
auto-block. DNS names are available to rule matching.

**Limitations:** DoH/DoT are TLS/HTTPS and hide names; DNS answers are only used
as metadata (no poisoning/cache logic).

## SOCKS4/4a and SOCKS5

Parses client greeting, method list, connect/bind/UDP-associate request, IPv4/
domain/IPv6 address, SOCKS4a hostnames, and SOCKS5 UDP headers. A complete SOCKS5
request is 0.97 `proxy`; a greeting alone is 0.72. SOCKS5 can be legitimate
management software, but it is an explicit proxy protocol; operators can
allowlist it.

## Plaintext VLESS

VLESS request layout: version (currently 0), 16-byte UUID, addons length, command
(1/2/3), port, address type, address. Axion validates every field, hostnames, and
address lengths. A structurally complete request with a v4-style UUID scores
0.95; other valid UUIDs 0.84. The request is a direct proxy finding.

This only fires when a VLESS header is **visible** (plaintext, misconfigured
fallback, or capture after a terminating proxy). VLESS inside TLS is not visible.
Axion does not claim to extract the UUID secret from encrypted sessions.

## Plaintext Trojan

Trojan request layout: 56 hex characters (SHA-224 password hash), CRLF, command,
address type/address, port, CRLF. Every field is validated; confidence is 0.97.
Trojan inside TLS is not visible.

## VMess

Modern VMess is AEAD-encrypted and has no reliable passive signature. Axion
implements a deliberately weak heuristic: a high-entropy opaque TCP stream on a
common proxy port produces `vmess-suspected` at 0.16–0.20. It is in the
`obfuscation` category and never auto-blocks. Do not treat it as identification.

## REALITY / XTLS

REALITY is designed to be indistinguishable from a real TLS connection to the
stealed SNI. Observable TLS traits (TLS 1.3, GREASE, h2+http/1.1 ALPN, 32-byte
session IDs, ECH) are also used by browsers and uTLS clients. Axion therefore
exposes `reality-suspected` at 0.15–0.28 and `xtls-suspected` at 0.15 for
long-lived TLS 1.3 flows. Both are `obfuscation` and never auto-block. Explicit
rules can match them with a custom threshold, at the operator's risk. XTLS
“TLS-in-TLS” traffic is encrypted to a passive observer; Axion does not claim to
detect it by decrypting.

Our benign TLS fixture (Chrome-like GREASE + h2/http1.1) intentionally triggers
the weak reality hypothesis; a regression test asserts it produces no event and
no block under default thresholds. This demonstrates why these findings are
quarantined from automatic enforcement.

## Transport and flow heuristics

- Packet-size histogram per direction (8 buckets), bytes/packets per direction,
  flow duration, first/last timestamps, TCP flags observed.
- WebSocket/gRPC transport findings are independent of payload contents.
- VMess/REALITY/XTLS heuristics only see metadata; they are not evidence of
  decryption.

## Event gating and deduplication

`detection::fingerprint` hashes sorted protocol names plus SNI/DNS names.
`detection::assess` selects security-relevant categories and gates events at
`general.monitor_confidence`. The engine suppresses duplicate events for the same
flow/fingerprint and emits on:
1. new security-relevant findings above the monitor threshold,
2. a new logging/monitor rule match,
3. the first actual block of a flow.

Events include timestamp, flow ID, endpoints, transport, protocol names,
categories, confidence, proxy score, evidence (bounded), matched rule, action,
blocked flag, mode, SNI and DNS names.

## False positives and anti-evasion

- Direct proxy findings require structurally valid, fully parsed handshakes.
- Random payloads can theoretically collide with a plaintext parser; the
  constrained field layouts make this unlikely, and explicit allowlists are
  available.
- Ordinary TLS never blocks due to TLS mimicry.
- IP fragment overlap conflicts discard the set; truncated input is not guessed.
- TCP retransmissions/out-of-order segments are handled; data beyond the
  reassembly cap is not classified.
- Weak findings remain visible in `/api/flows` even below the event threshold,
  so operators can investigate without auto-blocking.

## Extending

Implement `axion::dpi::ProtocolDetector` and register it with
`Classifier::register`; pass the classifier via `Engine::new_with_classifier`.
Detectors must be bounded and return evidence. No external executable or plugin
framework is involved.
