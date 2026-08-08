<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Clean-VM Windows E2E — personalized agent installer (issue #9)

This runbook validates the end-to-end personalized-installer flow on a **clean,
supported Windows VM**: an authorized technician downloads a site-scoped package
and the agent installs, enrolls, runs, upgrades, and uninstalls — with **no one
typing a server URL or enrollment token**. It also covers the negative cases
(replay, expiry, tampered artifact, unauthorized) and the audit evidence.

These are the acceptance items that cannot be verified by unit/integration tests
(they need a real Windows service + a fresh machine image), so this is a manual
release gate. Automated coverage of the server flow and installer contract
already lives in `server/tests/test_installer_downloads.py` and
`installer/test/test_installer_contract.py`.

> Run this on a throwaway VM you can snapshot and roll back. Enrolling a real
> machine writes a DPAPI-protected identity; always start each case from the
> clean snapshot so results are reproducible.

---

## 1. Scope — what this proves

| # | Acceptance criterion (issue #9) | Cases |
|---|---|---|
| 1 | Technician downloads a personalized package for one site and installs on a clean VM with no URL/token entry | A, E |
| 2 | Short-lived, limited-use token; never exposed in logs/history; rejects expired/revoked/replayed | B |
| 3 | Installed agent enrolls into the intended site; cross-site/unauthorized fail | A, F |
| 4 | Interactive installer still works with no preconfiguration | D |
| 5 | Download, enrollment, rejection, revocation produce secret-redacted audit evidence | G |
| — | Reinstall/upgrade and uninstall are clean | H, I |
| — | Tampered/unavailable artifact fails closed | C |

---

## 2. Prerequisites

**Server (staging or production-like):**

- Reachable over HTTPS at the origin compiled into the installer
  (`ProductionServerURL` in `installer/NodeLinkAgent.iss`). If testing against a
  different origin, build a test installer with that origin baked in.
- The personalized-download feature is configured (issue #9 settings):
  - `INSTALLER_ARTIFACT_PATH` → absolute path to the **built, signed** stock
    installer `.exe` on the server host.
  - `INSTALLER_ARTIFACT_SHA256` → the expected SHA-256 (hex) of that file
    (enables the fail-closed integrity check; set it for the tamper case).
  - `INSTALLER_ARTIFACT_VERSION` → e.g. `0.1.2`.
  - `INSTALLER_TOKEN_TTL_SECONDS` → optionally lower (e.g. `120`) to make the
    expiry case (B) fast.
  - Confirm: unset `INSTALLER_ARTIFACT_PATH` ⇒ the endpoint returns
    `503 installer_downloads_disabled` (case C).
- An **operator** account (role `operator` or `admin`) and its password.
- At least one **client → site** created; note the target `site_id`.
- A second **read-only** operator account for the authorization case.

**Windows VM (the endpoint):**

- A supported edition/version/arch per
  [`WINDOWS-SUPPORT-MATRIX.md`](./WINDOWS-SUPPORT-MATRIX.md) (x64).
- Local administrator login (the installer elevates via UAC).
- Outbound HTTPS to the server origin allowed.
- **A clean snapshot taken now**, before any install. Roll back to it between
  cases.
- No prior NodeLink install (verify: no `NodeLink RMM Agent` service, no
  `C:\Program Files\NodeLink\Agent`).

**Reference facts used below:**

- Service name: `NodeLink RMM Agent`
- Install dir: `C:\Program Files\NodeLink\Agent` (`rmm-agent.exe`)
- Runtime files: `config.json`, `identity.json`, `seen_commands.json`,
  `monitoring_state.json` (in the install dir)
- Log: `%ProgramData%\NodeLink\logs\rmm-agent.log`
- Sidecar file name inside the ZIP: `nodelink-enroll.token`
- Download endpoint: `POST /api/v1/sites/{site_id}/installer-package`

---

## 3. Obtain a personalized package

> The one-click **dashboard "Download installer" button is a follow-up**. Until
> it ships, drive the same authenticated endpoint directly. The token lands only
> inside the ZIP body — do not paste it anywhere.

Run from an admin PowerShell **on a trusted workstation** (not committed, not
emailed). Replace the origin, credentials, and `site_id`.

```powershell
$Server = "https://nodelink-backend-733e.onrender.com"
$SiteId = "<target-site-id>"

# 1. Authenticate as the operator -> bearer token (kept in memory only).
$login = Invoke-RestMethod -Method Post -Uri "$Server/api/v1/auth/login" `
  -ContentType "application/json" `
  -Body (@{ email = "tech@example.com"; password = "<password>" } | ConvertTo-Json)
$auth = @{ Authorization = "Bearer $($login.access_token)" }

# 2. Download the personalized ZIP (binary; -OutFile keeps it out of history).
Invoke-WebRequest -Method Post -Uri "$Server/api/v1/sites/$SiteId/installer-package" `
  -Headers $auth -OutFile "$env:USERPROFILE\Downloads\NodeLink-personalized.zip"
```

Confirm the response was `200`, `Content-Type: application/zip`, and
`Cache-Control: no-store`. Copy the ZIP to the VM (shared folder / RDP clipboard
file copy), then **extract it into its own folder** so `Setup.exe` sits beside
`nodelink-enroll.token`.

---

## 4. Cases

Roll back to the clean snapshot before **each** case.

### Case A — Personalized zero-touch install (the core)

1. On the VM, open the extracted folder. Confirm both files are present:
   `NodeLinkAgentSetup-<version>.exe` and `nodelink-enroll.token`.
2. Double-click the `.exe`. Accept the UAC elevation prompt.
3. **Watch the wizard: there must be NO enrollment-token page and NO server-URL
   page.** You should see welcome → install location → progress → "Setup
   Completed" only.
4. Finish the wizard.

**Verify (admin PowerShell on the VM):**

```powershell
Get-Service "NodeLink RMM Agent"        # Status = Running, StartType = Automatic
Test-Path "C:\Program Files\NodeLink\Agent\rmm-agent.exe"    # True
Test-Path "C:\Program Files\NodeLink\Agent\identity.json"    # True (enrolled)

# config.json points at the compiled-in origin and no longer holds a plaintext
# token after service-context enrollment rewrites it.
Get-Content "C:\Program Files\NodeLink\Agent\config.json"

# The token must NOT appear in the agent log.
Select-String -Path "$env:ProgramData\NodeLink\logs\rmm-agent.log" -Pattern "nlenr_" -Quiet
#   -> should be False (no match)
```

**Verify on the server/dashboard:**

- The new endpoint appears **under the intended site** (matching `site_id`).
- It heartbeats (last-seen updates within one interval).
- Audit log contains `installer_package.created` (from the download) and
  `agent.enrolled` (from this machine), and neither stores the token secret.

✅ **Pass A** when the install showed no token/URL prompt, the service is
running, the endpoint is enrolled under the correct site, and no `nlenr_` token
appears in the log or audit detail.

### Case B — Single-use, expiry, replay (token hardening)

Using the **same token** already consumed in Case A (from the same ZIP):

1. Roll back the VM to clean, re-run the installer from the **same** extracted
   folder (same sidecar token).
2. Expected: the agent CLI enrollment fails; the installer surfaces a
   registration error and the log shows an enrollment rejection. The service is
   **not** left running/enrolled.
   - Reason: the token is `max_uses=1` and was consumed in Case A → replay is
     rejected by the server enrollment path.
3. **Expiry:** with `INSTALLER_TOKEN_TTL_SECONDS` set low (e.g. 120s), download a
   fresh package, wait past the TTL, then install → enrollment must fail
   (expired).
4. **Revocation:** download a fresh package, revoke its enrollment token from the
   dashboard/API before installing, then install → enrollment must fail
   (revoked).

**Verify:** `agent.enrollment_failed` (or equivalent rejection) is audited for
each; no endpoint appears; no `identity.json` is written.

✅ **Pass B** when replayed, expired, and revoked tokens all fail closed with no
enrollment.

### Case C — Fail-closed artifact handling (server-side)

Performed against the **server**, no VM needed:

1. Unset `INSTALLER_ARTIFACT_PATH` → `POST .../installer-package` returns
   `503` with `code = installer_downloads_disabled`.
2. Point it at a missing file → `503 installer_artifact_unavailable`.
3. Set `INSTALLER_ARTIFACT_SHA256` to a wrong digest → `503
   installer_artifact_integrity`, and an `installer_package.rejected` audit
   event is recorded; **no token or download record is created**.

✅ **Pass C** when all three refuse with the documented codes and the tamper case
is audited.

### Case D — Interactive fallback (plain stock installer)

1. Copy **only** `NodeLinkAgentSetup-<version>.exe` to the VM (no sidecar file).
2. Run it. Expected: the **enrollment-token page appears** (unchanged legacy
   behavior). Paste a valid token from the dashboard, continue.

**Verify:** service Running, endpoint enrolled under the token's site.

✅ **Pass D** when the interactive prompt still works with no preconfiguration.

### Case E — Silent / mass deployment

From an elevated prompt on a clean VM, with a valid token:

```powershell
.\NodeLinkAgentSetup-<version>.exe /VERYSILENT /TOKEN=<token>
```

Or drop the sidecar beside the exe and run `/VERYSILENT` with no `/TOKEN=`.

**Verify:** no wizard shown (UAC only), service Running, endpoint enrolled.

✅ **Pass E** when the silent install enrolls with no interactive input.

### Case F — Cross-site / unauthorized (server-side)

1. As a **read-only** operator, `POST .../installer-package` → `403`.
2. Unauthenticated (no bearer) → `401`.
3. Unknown `site_id` → `404`.

✅ **Pass F** when unauthorized and cross-site requests are refused.

### Case G — Audit evidence & redaction

After Cases A–B, pull the audit timeline (dashboard Audit view or API) and
confirm:

- `installer_package.created` — carries `site_id`, `download_id`,
  `enrollment_token_id`, `artifact_version`, `artifact_sha256`,
  `token_expires_at`; **no token value**.
- `installer_package.rejected` — coded `reason` only (from Case C).
- `agent.enrolled` and enrollment-failure events for the replay/expiry/revoke
  attempts.
- Search every event's detail for the `nlenr_` token string → **absent**.
- Chain/anchor verification (if run) still passes over the new events.

✅ **Pass G** when all expected events exist and no secret is present.

### Case H — Reinstall / upgrade

1. From an already-installed VM (Case A state), run a personalized install again
   (fresh token) — or a newer `<version>` build.
2. Expected: the installer stops/deregisters the previous service, overwrites the
   binary, re-enrolls, and starts cleanly. Service Running afterward.

✅ **Pass H** when the upgrade/reinstall completes without manual cleanup.

### Case I — Uninstall

1. Uninstall via **Settings → Apps** (or `Control Panel → Programs`).
2. **Verify:**

```powershell
Get-Service "NodeLink RMM Agent" -ErrorAction SilentlyContinue   # gone
Test-Path "C:\Program Files\NodeLink\Agent"                       # False (or empty)
```

The runtime files (`config.json`, `identity.json`, `seen_commands.json`,
`monitoring_state.json`) are removed. The endpoint may remain visible on the
server as last-seen/offline (expected — uninstall does not delete server-side
history).

✅ **Pass I** when the service is deregistered and the install dir is cleaned.

---

## 5. Pass/fail checklist

- [ ] A — Zero-touch install: no token/URL prompt; service Running; enrolled under the intended site
- [ ] B — Replayed / expired / revoked tokens all fail closed
- [ ] C — Disabled / missing / tampered artifact → documented `503` codes; tamper audited
- [ ] D — Interactive prompt still works with a plain installer
- [ ] E — Silent `/TOKEN=` (and sidecar `/VERYSILENT`) enrolls with no input
- [ ] F — Read-only `403`, unauthenticated `401`, unknown site `404`
- [ ] G — Audit events present and secret-redacted; no `nlenr_` in any detail or log
- [ ] H — Reinstall/upgrade is clean
- [ ] I — Uninstall removes the service and runtime files

---

## 6. Evidence to capture (for the release record)

- Screenshot of the wizard **without** a token page (Case A).
- `Get-Service` output showing Running (A/E/H) and absent (I).
- The redacted `config.json` after enrollment.
- Audit export (or screenshots) for `installer_package.created`,
  `agent.enrolled`, and the rejection cases.
- The `503` response bodies for Case C.

Attach these to the release checklist alongside
[`RELEASING.md`](./RELEASING.md).

---

## 7. Cleanup

- Roll the VM back to the clean snapshot (discard all enrollment state).
- Revoke any enrollment tokens minted during testing that were not consumed.
- Restore any temporarily lowered server settings (e.g.
  `INSTALLER_TOKEN_TTL_SECONDS`, `INSTALLER_ARTIFACT_SHA256`).
- Delete downloaded ZIPs and extracted folders from the workstation and VM.
