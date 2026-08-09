#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
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

# Prove the ldflags stamp actually took (issue #179). A release artifact that
# still reports the 0.1.0-dev fallback looks like a stale build to every
# operator and to the dashboard, so refuse to hand one back. Only the artifact
# matching the host can be executed here; the three targets share one LDFLAGS,
# so verifying that one verifies the stamp.
HOST_TARGET="$(go env GOOS)/$(go env GOARCH)"
case "$HOST_TARGET" in
  linux/amd64)   VERIFY="$OUT/rmm-agent-linux-amd64" ;;
  darwin/arm64)  VERIFY="$OUT/rmm-agent-darwin-arm64" ;;
  windows/amd64) VERIFY="$OUT/rmm-agent-windows-amd64.exe" ;;
  *)             VERIFY="" ;;
esac
if [ -n "$VERIFY" ]; then
  echo " -> verifying embedded version"
  "$VERIFY" version --expect "$VERSION" >/dev/null
else
  echo " !! host is $HOST_TARGET; no built artifact can run here to verify the version stamp" >&2
fi

echo "Done. Binaries in ./$OUT"
ls -lh "$OUT"
