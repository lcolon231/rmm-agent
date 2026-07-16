# Deploying NodeLink RMM with TLS

Agents authenticate with long-lived bearer tokens and operators with JWTs. On
plain HTTP, both cross the network in cleartext — so **TLS is mandatory the
moment the server is reachable from anywhere but localhost** (threat-model
gap #4). Command *authenticity* does not depend on TLS (commands are Ed25519-
signed and the agent refuses anything that fails verification), but token
confidentiality and telemetry privacy do.

The scaffold itself does not terminate TLS. The supported pattern is a
TLS-terminating reverse proxy in front of uvicorn:

```
Agent ── https:// ──► Caddy (:443, TLS) ── http:// ──► uvicorn (127.0.0.1:8000)
```

## Option A (recommended): Caddy with a public DNS name

Caddy obtains and renews Let's Encrypt certificates automatically. You need a
DNS name pointing at the server and ports 80/443 reachable from the internet.

1. Install Caddy v2 (<https://caddyserver.com/docs/install>).
2. Edit `deploy/Caddyfile`: replace `rmm.example.com` with your DNS name.
3. Start uvicorn bound to localhost only, with proxy headers enabled so the
   app sees real client IPs (matters for audit and future rate-limiting):

   ```bash
   cd server
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --proxy-headers
   ```

4. Start Caddy:

   ```bash
   caddy run --config deploy/Caddyfile
   ```

5. Verify from another machine: `curl https://rmm.example.com/healthz` must
   return `{"status":"ok",...}` with no certificate warnings.

Because uvicorn binds `127.0.0.1`, the plain-HTTP port is unreachable from the
network — HTTPS is effectively enforced, not optional.

## Option B: uvicorn's built-in TLS (no proxy)

If you already have a certificate and key (from your own CA or ACME tooling),
uvicorn can terminate TLS directly:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 443 \
  --ssl-certfile /path/fullchain.pem --ssl-keyfile /path/privkey.pem
```

You are then responsible for renewal and for not also exposing a plain-HTTP
listener. The proxy pattern (Option A) is less to get wrong.

## LAN / no public DNS

Let's Encrypt cannot issue for private names, so use Caddy's internal CA:
uncomment `tls internal` in `deploy/Caddyfile`. Caddy then signs with its own
root certificate, which each endpoint must trust — export it from the Caddy
host (`~/.local/share/caddy/pki/authorities/local/root.crt`, or
`%AppData%\Caddy\pki\authorities\local\root.crt` on Windows) and install it
into the endpoint's trust store (Windows: `certutil -addstore -f Root
root.crt` from an elevated prompt).

The Go agent uses the OS trust store and **correctly refuses** untrusted
certificates. If enrollment or check-ins fail with a certificate error, fix
trust — do not weaken verification. There is deliberately no
"skip TLS verify" option in the agent.

## Pointing the agent at HTTPS

For a **new** agent: set `"server_url": "https://rmm.example.com"` in
`config.json` before first run.

For an **already-enrolled** agent, note that `server_url` is captured into
`identity.json` at enrollment and used from there — editing `config.json`
alone changes nothing. Either:

- edit `identity.json` (beside the config; the service reads the copy next to
  the binary) and change `server_url` to the `https://` URL, then restart the
  service; or
- delete `identity.json` and re-enroll with a fresh enrollment token.

The first option keeps the agent's identity and history; prefer it.

## Checklist

- [ ] `https://<host>/healthz` returns OK from another machine, no cert warnings
- [ ] uvicorn is bound to `127.0.0.1` (Option A) — plain HTTP unreachable externally
- [ ] uvicorn started with `--proxy-headers`
- [ ] agent `identity.json` / `config.json` use `https://`
- [ ] agent log shows check-ins succeeding (silence after startup = success)
- [ ] server marks the agent `online`

## Future hardening (out of scope here)

- **Certificate pinning in the agent** for high-assurance clients (threat
  model, boundary 2).
- **HSTS / redirect** of any legacy plain-HTTP listeners.
