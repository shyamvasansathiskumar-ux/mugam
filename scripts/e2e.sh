#!/usr/bin/env bash
# Browser end-to-end test: starts a fresh server with empty data, runs tests/e2e.py
# (Playwright + Chromium, fake camera showing a still photo), then stops the server.
set -e
cd "$(dirname "$0")/.."
bash scripts/build.sh > /dev/null
DATA=$(mktemp -d); PORT=${PORT:-8790}
java -cp server/out mugam.Server --port "$PORT" --origin "http://localhost:$PORT" --data "$DATA" --web docs > "$DATA/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; rm -rf "$DATA"' EXIT
for i in $(seq 1 30); do curl -sf "http://localhost:$PORT/api/health" > /dev/null && break; sleep 0.3; done
python3 -m http.server 8791 --bind 127.0.0.1 --directory docs > /dev/null 2>&1 &
PY=$!
trap 'kill $PID $PY 2>/dev/null; rm -rf "$DATA"' EXIT
sleep 1
MUGAM_URL="http://localhost:$PORT" MUGAM_DEMO_URL="http://127.0.0.1:8791/try.html" python3 tests/e2e.py
