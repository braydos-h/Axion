#!/usr/bin/env bash
# Start the compiled binary without capture privileges and compare the served
# assets to the checked-out sources. The temporary config avoids user state.
set -euo pipefail
binary=$(realpath "${1:?path to compiled Axion binary is required}")
tmp=$(mktemp -d)
pid=""
cleanup() {
  if [[ -n "$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT
export HOME="$tmp" XDG_CONFIG_HOME="$tmp/config" AXION_AI_ENABLED=false
"$binary" demo --web-host 127.0.0.1 --web-port 0 --strict-port --no-browser >"$tmp/axion.log" 2>&1 &
pid=$!
ready=false
url=""
for _ in $(seq 1 100); do
  if ! kill -0 "$pid" 2>/dev/null; then break; fi
  # The application prints its own OS-assigned listener only after binding it.
  url=$(sed -n 's/^Axion dashboard: \(http:\/\/127\.0\.0\.1:[0-9][0-9]*\/\)$/\1/p' "$tmp/axion.log" | head -n 1)
  if [[ -n "$url" ]] && curl --fail --silent "${url}api/health" >/dev/null && kill -0 "$pid" 2>/dev/null; then
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  cat "$tmp/axion.log" >&2
  echo "Demo dashboard failed to start" >&2
  exit 1
fi
for asset in index.html style.css app.js; do
  path="$asset"
  [[ "$asset" != index.html ]] || path=""
  kill -0 "$pid"
  curl --fail --silent "${url}${path}" >"$tmp/$asset"
  cmp "web/$asset" "$tmp/$asset"
done
# Demo must actually produce packets without capture privileges.
for _ in $(seq 1 50); do
  if curl --fail --silent "${url}api/stats" | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["packets_captured"] > 0 else 1)'; then
    exit 0
  fi
  kill -0 "$pid"
  sleep 0.1
done
echo "Demo did not produce packets" >&2
exit 1
