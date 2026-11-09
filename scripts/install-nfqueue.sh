#!/usr/bin/env bash
# Install or remove an nftables NFQUEUE policy for Axion.
#
# Usage:
#   sudo ./scripts/install-nfqueue.sh [--remove] [fail-open|fail-closed] [queue-num]
#
# Defaults to fail-open and queue 0. Only the forward hook is installed, so
# router deployments are affected; local host input/output is intentionally not
# queued. Edit the generated table to match your interfaces/ports.
set -euo pipefail

TABLE="axion_dpi"
MODE="fail-open"
QUEUE="0"
REMOVE=0

for arg in "$@"; do
  case "$arg" in
    --remove) REMOVE=1 ;;
    fail-open|fail-closed) MODE="$arg" ;;
    ''|*[!0-9]*) echo "unknown argument: $arg" >&2; exit 2 ;;
    *) QUEUE="$arg" ;;
  esac
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "must run as root (or via sudo)" >&2
  exit 1
fi
if ! command -v nft >/dev/null 2>&1; then
  echo "nft is required (install nftables)" >&2
  exit 1
fi

if [[ "$REMOVE" -eq 1 ]]; then
  nft delete table inet "$TABLE" 2>/dev/null || true
  echo "removed inet $TABLE"
  exit 0
fi

# Loading the module is best-effort; kernels may build it in.
modprobe nfnetlink_queue 2>/dev/null || true

BYPASS=""
if [[ "$MODE" == "fail-open" ]]; then
  # The nftables queue `bypass` flag accepts packets if no userspace listener
  # is attached. NFQA_CFG_F_FAIL_OPEN additionally handles a full queue.
  BYPASS="bypass"
fi

PORTS="${AXION_NFQUEUE_PORTS:-80,443,8080,8443}"
if [[ ! "$PORTS" =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  echo "AXION_NFQUEUE_PORTS must be a comma-separated numeric port list" >&2
  exit 2
fi

nft delete table inet "$TABLE" 2>/dev/null || true
nft -f - <<EOF
table inet $TABLE {
  chain forward {
    type filter hook forward priority filter; policy accept;

    # Management and rescue paths must never enter the queue.
    tcp dport 22 accept comment "axion: management bypass"
    tcp dport 8787 accept comment "axion: dashboard/API bypass"
    ip daddr 127.0.0.0/8 accept
    ip6 daddr ::1 accept

    tcp dport { $PORTS } queue num $QUEUE $BYPASS
    udp dport { $PORTS } queue num $QUEUE $BYPASS
  }
}
EOF

echo "installed inet $TABLE (queue $QUEUE, $MODE, ports: $PORTS)"
echo "verify: nft list table inet $TABLE"
echo "remove: sudo $0 --remove"
