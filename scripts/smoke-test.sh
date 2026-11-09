#!/usr/bin/env bash
# Release-binary smoke test. Runs without root: API-only mode, offline pcap,
# embedded dashboard and the status/rules CLI paths.
set -euo pipefail

BIN="${1:-target/release/axion}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
PID=""

cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" 2>/dev/null; then
    kill -TERM "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "[smoke] binary: $BIN"
"$BIN" --version
"$BIN" --help >/dev/null

echo "[smoke] offline pcap inspection"
"$BIN" inspect --pcap "$ROOT/tests/fixtures/benign_tls.pcap" --json > "$TMP/tls.json"
python3 - "$TMP/tls.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["records"] == 1, report
assert report["flows"][0]["sni"] == "www.example.com", report["flows"]
assert report["events"] == [], "benign TLS must not emit a security event"
print("[smoke] TLS fixture parsed, SNI extracted, no false-positive event")
PY

PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

cat > "$TMP/axion.toml" <<EOF
[general]
mode = "monitor"
max_flows = 1000
event_capacity = 64

[capture]
backend = "none"
interface = "lo"

[api]
enabled = true
bind = "127.0.0.1:$PORT"

[telemetry]
sample_interval_ms = 200
history_seconds = 10

[firewall]
bypass_tcp_ports = []
bypass_cidrs = ["127.0.0.0/8"]
EOF

"$BIN" --config "$TMP/axion.toml" config check >/dev/null
"$BIN" --config "$TMP/axion.toml" start >"$TMP/axion.log" 2>&1 &
PID=$!

ready=0
for _ in $(seq 1 100); do
  if curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "[smoke] axion exited early:" >&2
    cat "$TMP/axion.log" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$ready" -ne 1 ]]; then
  echo "[smoke] API did not become ready" >&2
  cat "$TMP/axion.log" >&2
  exit 1
fi

echo "[smoke] embedded dashboard"
curl -fsS "http://127.0.0.1:$PORT/" > "$TMP/index.html"
grep -q "AXION" "$TMP/index.html"
curl -fsS "http://127.0.0.1:$PORT/dashboard.js" > "$TMP/dashboard.js"
grep -q "refreshStatus" "$TMP/dashboard.js"
curl -fsS "http://127.0.0.1:$PORT/api/status" > "$TMP/status.json"
python3 - "$TMP/status.json" <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
assert status["mode"] == "monitor", status
assert status["can_enforce"] is False, status
assert status["metrics"]["packets_total"] == 0, status
print("[smoke] API status valid")
PY

echo "[smoke] CLI status / rules list"
"$BIN" --config "$TMP/axion.toml" status > "$TMP/cli-status.txt"
grep -q "mode=monitor" "$TMP/cli-status.txt"
"$BIN" --config "$TMP/axion.toml" rules list > "$TMP/cli-rules.txt"
grep -q "rules compiled" "$TMP/cli-rules.txt"

echo "[smoke] detection fixture"
"$BIN" inspect --pcap "$ROOT/tests/fixtures/proxy_socks5.pcap" --json > "$TMP/socks.json"
python3 - "$TMP/socks.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
assert report["events"], "expected SOCKS5 detection"
assert report["events"][0]["protocols"][0] == "socks5"
assert report["events"][0]["blocked"] is False
print("[smoke] SOCKS5 detection reported in monitor-only inspection")
PY

kill -TERM "$PID"
wait "$PID" || true
PID=""
echo "[smoke] OK"
