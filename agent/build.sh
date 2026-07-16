#!/usr/bin/env bash
# Build the NodeLink RMM agent for common targets.
# Usage: ./build.sh [version]
set -euo pipefail

VERSION="${1:-0.1.0-dev}"
LDFLAGS="-s -w -X main.version=${VERSION}"
OUT="bin"
mkdir -p "$OUT"

echo "Building NodeLink RMM agent ${VERSION}"

echo " -> windows/amd64"
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$OUT/rmm-agent-windows-amd64.exe" ./cmd/agent

echo " -> linux/amd64"
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$OUT/rmm-agent-linux-amd64" ./cmd/agent

echo " -> darwin/arm64"
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o "$OUT/rmm-agent-darwin-arm64" ./cmd/agent

echo "Done. Binaries in ./$OUT"
ls -lh "$OUT"
