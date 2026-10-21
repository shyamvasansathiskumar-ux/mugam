#!/usr/bin/env bash
# Runs every automated test: Java server (protocol, attacks, HTTP) and the browser logic (Node).
# The browser end-to-end test (tests/e2e.py, needs Playwright + Chromium) is run separately.
set -e
cd "$(dirname "$0")/.."
bash scripts/build.sh > /dev/null
java -cp server/out mugam.TestRunner
node tests/web.test.mjs
