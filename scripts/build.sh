#!/usr/bin/env bash
# Compiles the server and its tests into server/out. Needs JDK 21. No other dependencies.
set -e
cd "$(dirname "$0")/../server"
rm -rf out && mkdir -p out
javac -encoding UTF-8 -d out $(find src test -name "*.java")
echo "Built into server/out/"
