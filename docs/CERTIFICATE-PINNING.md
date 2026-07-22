# Optional TLS SPKI certificate pinning

NodeLink agents can optionally add leaf public-key pinning to normal TLS
validation for high-assurance deployments. Pinning is off by default. It does
not replace the operating system trust store, certificate time checks, or
hostname validation: when configured, **both** normal PKI and one pin must pass.

## Design and pin format

`config.json` accepts `tls_spki_pins`, an array of one or more strings:

```json
{
  "server_url": "https://rmm.example.com",
  "enrollment_token": "one-time-token",
  "tls_spki_pins": [
    "sha256/BASE64_SHA256_OF_CURRENT_LEAF_SPKI",
    "sha256/BASE64_SHA256_OF_NEXT_LEAF_SPKI"
  ]
}
```

Each value is exactly `sha256/` followed by standard padded base64 encoding of
the 32-byte SHA-256 digest of the leaf certificate's DER
`SubjectPublicKeyInfo`. A certificate reissued with the same key keeps the same
pin. A new key requires a new pin. Malformed pins and pins combined with a
non-HTTPS server URL are fatal configuration errors.

Pins remain in static `config.json`; they are deliberately not copied into the
encrypted `identity.json`. This lets an operator stage or recover pins without
re-enrolling and ensures an already-enrolled agent reads the current pin set on
restart. `server_url` still comes from the enrolled identity, so changing that
URL follows the separate procedure in `DEPLOYMENT-TLS.md`.

The HTTP client leaves Go's `InsecureSkipVerify` false. After Go validates the
chain, certificate time, and hostname, the client hashes the leaf SPKI and
compares it in constant time with every configured pin. No match fails closed;
the error log includes the observed public pin to aid an out-of-band incident
investigation.

## Derive a pin safely

Obtain and verify the certificate through an authenticated administrative
channel. Do not build the initial trust decision from the same untrusted network
path pinning is intended to defend. With OpenSSL:

```bash
PIN="$(openssl s_client -connect rmm.example.com:443 -servername rmm.example.com </dev/null 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A)"
printf 'sha256/%s\n' "$PIN"
```

Compare the result with a value produced directly from the certificate or key
under operator control. A next-key pin can be generated before certificate
issuance from that key's public key/CSR toolchain.

## Rotation procedure (current + next overlap)

Never replace a sole pin and the server key in one step.

1. Generate the next private key under the deployment's key-custody policy and
   obtain its SPKI pin through a trusted channel.
2. Add the next pin beside the current pin in every agent's `config.json`.
   Restart the agent service and confirm the full fleet checks in. Keep the
   current certificate and key active during this propagation window.
3. Issue/install a normally valid certificate for the next key. Verify its
   chain, hostname, validity period, and SPKI before switching traffic.
4. Rotate the server to the next certificate/key. Confirm check-ins across at
   least one full heartbeat interval plus the deployment's offline-agent
   allowance. Investigate any agent that did not receive the overlap config.
5. Remove the old pin only after the overlap window and restart agents again.
   Retain the incident-approved rollback material for the declared recovery
   period, then destroy old private keys according to policy.

During steps 2–4, either public key matches. To roll back the server rotation,
restore the previous **still-valid** certificate/key while its pin remains in
the overlap set.

## Stale or expired pin recovery

A pin is not an exception to certificate validity. An expired-but-pinned
certificate fails standard TLS validation before it can be accepted. Recover in
this order:

1. If the private key for any configured pin remains available, issue and
   deploy a new, currently valid certificate for that same key and hostname.
   The SPKI pin remains valid, so agents recover without config changes.
2. If no pinned key can serve a valid certificate, update `config.json`
   out-of-band (endpoint management, console, or reinstall) to add the verified
   new pin, then restart the agent. Keep multiple pins until fleet recovery is
   proven.
3. As an explicitly approved incident fallback, remove `tls_spki_pins` or set it
   to `[]` out-of-band and restart. The agent returns to normal PKI validation;
   it never disables chain or hostname checks. Re-establish pins through a
   trusted channel after service is restored.

When every pin is stale the agent cannot receive a remote fix through NodeLink,
because the very TLS connection needed to deliver it fails closed. Plan and
test the out-of-band path before enabling pinning. Keep certificate-expiry
monitoring; pin overlap does not solve an expired certificate.

## Verification checklist

- [ ] At least current and next pins are present before a key rotation.
- [ ] Every pin was derived and compared through a trusted channel.
- [ ] Standard `curl`/browser validation reports a valid chain and hostname.
- [ ] Agents check in after config restart and after certificate rotation.
- [ ] A canary with a deliberately wrong pin fails closed and executes no work.
- [ ] Offline endpoints and the overlap duration are accounted for.
- [ ] Reissue-with-pinned-key and out-of-band config recovery are rehearsed.
