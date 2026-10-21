#!/usr/bin/env bash
# Builds and runs Mugam locally:  bash scripts/serve.sh [port]   (data in ./data)
set -e
cd "$(dirname "$0")/.."
PORT=${1:-8080}
bash scripts/build.sh > /dev/null
exec java -cp server/out mugam.Server --port "$PORT" --origin "http://localhost:$PORT" --data "${MUGAM_DATA:-data}" --web docs
