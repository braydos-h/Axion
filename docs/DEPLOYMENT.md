# Deployment and operations

## Permissions

| Feature | Requirement |
|---|---|
| `inspect --pcap` | none |
| `status`, `rules list` (client) | network access to the API; token if configured |
| AF_PACKET passive capture | root or `CAP_NET_RAW` |
| libpcap passive capture | root or `CAP_NET_RAW` + `libpcap.so` |
| NFQUEUE inline enforcement | root or `CAP_NET_ADMIN` |
| Installing nftables rules | root or `CAP_NET_ADMIN` in the network namespace |

Capability example:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/axion
getcap /usr/local/bin/axion
```

`CAP_NET_ADMIN` is powerful. Prefer a dedicated user and systemd
`AmbientCapabilities` over file capabilities where possible. The sample unit is
in `packaging/axion.service`.

## Kernel and package prerequisites

- Linux with `AF_PACKET`, `NETLINK_NETFILTER`, `NETFILTER_XT_TARGET_NFQUEUE` or
  nftables `queue`.
- nftables (`nft`) for inline deployments.
- Optional libpcap runtime (`libpcap0.8` on Debian/Ubuntu) if using
  `capture.backend = "libpcap"`. Axion loads it dynamically; no build headers are
  needed.
- A C linker/toolchain only to build Axion.

Check queue support:

```bash
lsmod | grep nfnetlink_queue || sudo modprobe nfnetlink_queue
cat /proc/net/netfilter/nfnetlink_queue
nft --version
```

## Passive monitoring

```bash
sudo axion --config /etc/axion/axion.toml start --interface eth0 --mode monitor
```

AF_PACKET sees frames on the interface, including outgoing frames by default.
Loopback shows a synthetic Ethernet header. Passive capture **never** modifies or
drops packets, even if rules return DROP; status/dashboard show the would-be
action and `blocked=false`.

Use `include_outgoing = false` to skip locally originated frames if the kernel
supports `PACKET_IGNORE_OUTGOING`; Axion logs a warning if the option is
unavailable.

## Inline enforcement with nftables

NFQUEUE rules decide which traffic enters Axion. The bundled helper installs a
forward-hook policy for common proxy/server ports:

```bash
sudo scripts/install-nfqueue.sh fail-open 0
# or
sudo scripts/install-nfqueue.sh fail-closed 0
```

Equivalent nftables rule:

```nft
table inet axion_dpi {
  chain forward {
    type filter hook forward priority filter; policy accept;

    tcp dport 22 accept
    tcp dport 8787 accept
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1 accept

    tcp dport { 80, 443, 8080, 8443 } queue num 0 bypass
    udp dport { 80, 443, 8080, 8443 } queue num 0 bypass
  }
}
```

Then:

```bash
sudo axion --config /etc/axion/axion.toml start --mode enforce
# or, to start in monitor while keeping runtime switching available:
sudo axion --config /etc/axion/axion.toml start --inline --mode monitor

# A dry-run inline example with an explicit decoded-proxy rule:
sudo axion --config config/axion.inline.example.toml start
```

`--mode enforce` implies inline NFQUEUE; the `--interface` argument is ignored
because queue rules define the traffic path.

### Forward vs local traffic

The sample hooks **forward**, appropriate for a router/bridge. To inspect traffic
originated by or destined to the host, add `output` and/or `input` hooks. Be
extremely careful:

- Queueing the management SSH/API flow prevents you from fixing a bad policy.
- Always bypass your management ports and loopback in nftables instead of relying
  only on Axion's `firewall.bypass_*`; a queued packet still waits for userspace.
- Test in a lab or with a serial/out-of-band console.

### Fail-open vs fail-closed

There are two independent mechanisms:

1. **nftables `bypass` flag**: if no userspace listener is attached, the kernel
   accepts the packet. This is what protects the host when Axion is stopped.
2. **`firewall.fail_open`**: sets `NFQA_CFG_F_FAIL_OPEN`; when the queue is full,
   the kernel accepts instead of dropping.

Axion fails startup if it cannot bind its queue; it will not silently run while
claiming enforcement. If boot ordering can race, load the nftables rule with
`bypass` first, then start Axion; remove `bypass` only after confirming the
listener is healthy. For fail-closed, remove `bypass` and set
`firewall.fail_open = false`, then ensure restart supervision and boot ordering.

Runtime NFQUEUE receive/send errors are logged and counted
(`metrics.enforcement_errors`). The one ordered verdict loop is intentionally
simple; if it exits unexpectedly (closed socket/permission loss), Axion shuts
down so systemd restart policy and kernel/nftables fail flags govern the
outcome. Monitor `/api/status`, `enforcement_errors` and the service state.

### Fragmentation and first-packet behaviour

NFQUEUE verdicts are per packet. Axion reassembles IP fragments internally for
classification, but the individual fragments have already received verdicts;
earlier fragments may be accepted before a later fragment completes the picture.
Likewise, a TCP flow can have its SYN/first payload accepted before the client
hello reveals a blockable SNI. Subsequent packets in a blocked flow are dropped.
For strict fragment policy, ensure defragmentation happens before the queue hook
(conntrack/nftables defrag) and/or add a dedicated fragment policy.

### REJECT

NFQUEUE provides ACCEPT and DROP. Axion maps `reject` to DROP
(`firewall.reject_emulation = "drop"`). If you need TCP RST or ICMP unreachable,
add a higher-priority nftables reject rule for the target traffic.

## Run as a service

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin axion
sudo install -m 0755 target/release/axion /usr/local/bin/axion
sudo install -m 0644 config/axion.example.toml /etc/axion/axion.toml
sudo install -m 0644 packaging/axion.service /etc/systemd/system/axion.service
sudo systemctl daemon-reload
sudo systemctl enable --now axion
```

The unit starts in monitor mode. For inline, edit `ExecStart` to add
`--mode enforce`, install queue rules first, and verify with `axion status`.
Use systemd overrides (`systemctl edit axion`) rather than editing packaged files.

## Dashboard and API

Default: `http://127.0.0.1:8787/` bound to loopback. For remote access, prefer an
SSH tunnel or authenticated reverse proxy. If binding non-loopback, set a long
random token:

```toml
[api]
bind = "0.0.0.0:8787"
token = "use-a-secret-manager"
```

or `AXION_API_TOKEN`. Configuration validation rejects a non-loopback bind
without a token unless `allow_insecure_remote = true` is explicitly set. The
dashboard asks for the token in the browser; it is kept in `sessionStorage`.

The token protects `/api/*`. Static dashboard files are public by design because
navigation cannot set a bearer header; they contain no live data.

## Capacity planning

- Set `general.max_flows` to roughly your peak concurrent connections plus
  headroom; the table evicts oldest-idle entries. A measured TLS-heavy replay
  used roughly 6.0 KiB peak RSS per live flow in this build (process baseline
  included); plan capacity from your own flow mix.
- `max_reassembly_bytes` is per TCP direction per flow. 256 KiB is generous for
  handshake/metadata; lower it on memory-constrained routers.
- Capture `queue_capacity` × snaplen bounds in-flight capture memory.
- `firewall.queue_max_len` bounds kernel queue memory.
- One NFQUEUE verdict loop processes packets serially; size queues for bursts and
  monitor `enforcement_errors`. Passive mode uses multiple workers.
- Event history is bounded by `event_capacity`; rate history by
  `history_seconds`.

## Verification and troubleshooting

```bash
axion status
curl -s http://127.0.0.1:8787/api/health
nft list table inet axion_dpi
cat /proc/net/netfilter/nfnetlink_queue
journalctl -u axion -f
```

| Symptom | Checks |
|---|---|
| `AF_PACKET socket failed` | root/`CAP_NET_RAW`; interface name |
| `bind netlink socket failed` | root/`CAP_NET_ADMIN` |
| Traffic hangs after starting | queue rule without `bypass`, Axion not running/crashed |
| No inline drops | nft rule port/chain missing; `status` mode/enforcement; queue number match |
| `libpcap.so not found` | install runtime package or use `af_packet` |
| Dashboard 401 | configure/enter token |
| Rules reload 400 | `axion rules validate`; prior rules stay active |
| High capture_drops | raise queue_capacity or reduce packet rate/workers |

## Smoke test without privileges

```bash
bash scripts/smoke-test.sh target/release/axion
```

This runs offline pcap analysis, starts an API-only instance (`capture.backend =
"none"`), verifies the embedded dashboard/API, runs CLI status/rules, checks a
SOCKS5 detection fixture, and shuts down cleanly.
