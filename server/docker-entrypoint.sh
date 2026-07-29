#!/usr/bin/env sh
# NodeLink backend container entrypoint.
set -e

# Production requires an HTTPS, non-loopback PUBLIC_BASE_URL (app/core/prodcheck.py).
# Render injects RENDER_EXTERNAL_URL (https://<service>.onrender.com); use it unless
# PUBLIC_BASE_URL was set explicitly (e.g. a custom domain).
export PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-$RENDER_EXTERNAL_URL}"

# Host-agnostic signing-key delivery: if the Ed25519 PEM was supplied as base64 in
# COMMAND_SIGNING_KEY_B64 and no key file exists yet, materialize it. On Render we
# instead mount a Secret File at COMMAND_SIGNING_KEY_PATH, so this block is skipped.
KEY_PATH="${COMMAND_SIGNING_KEY_PATH:-command_signing_key.pem}"
if [ -n "${COMMAND_SIGNING_KEY_B64:-}" ] && [ ! -f "$KEY_PATH" ]; then
  echo "$COMMAND_SIGNING_KEY_B64" | base64 -d > "$KEY_PATH"
  chmod 600 "$KEY_PATH"
fi

exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-10000}"
