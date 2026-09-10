# Assigns a global offline-check monitoring policy to the NodeLink deployment.
# Without this, offline alert evaluation is policy-gated and produces nothing
# even when the server already knows an endpoint is offline.
#
# Run this in your own PowerShell window (it prompts for a password).

param(
    [string]$BaseUrl = 'https://nodelink-backend-733e.onrender.com'
)

$ErrorActionPreference = 'Stop'
$base = $BaseUrl

Write-Host "NodeLink offline-check policy setup" -ForegroundColor Cyan
Write-Host "Server: $base`n"

# --- 1. Sign in -------------------------------------------------------------
$email = Read-Host "Operator email"
$secure = Read-Host "Password" -AsSecureString
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))

$loginBody = @{ email = $email; password = $plain } | ConvertTo-Json
try {
    $login = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method POST `
        -ContentType 'application/json' -Body $loginBody -TimeoutSec 60
} catch {
    Write-Host "`nLogin failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "A 401 means bad credentials. A 429 means too many attempts; wait and retry."
    exit 1
} finally {
    $plain = $null; $loginBody = $null
}

$accessToken = $login.access_token

if (-not $accessToken) {
    # Password was correct but a second factor applies. WebAuthn needs a browser
    # and your authenticator, so it cannot be completed from a script. A
    # single-use recovery code is the scriptable path and is exactly what these
    # codes exist for.
    Write-Host "`nSecond factor required." -ForegroundColor Yellow
    if ($login.methods) { Write-Host "Methods offered: $($login.methods -join ', ')" }
    Write-Host "WebAuthn needs a browser, so this uses a single-use recovery code."
    Write-Host "It will be consumed. You can mint fresh codes afterwards by signing"
    Write-Host "in to the dashboard normally with your authenticator.`n"

    $code = Read-Host "Recovery code (blank to abort)"
    if ([string]::IsNullOrWhiteSpace($code)) { Write-Host "Aborted."; exit 1 }

    try {
        $mfa = Invoke-RestMethod -Uri "$base/api/v1/auth/mfa/login/recovery-code" -Method POST `
            -Headers @{ Authorization = "Bearer $($login.mfa_token)" } `
            -ContentType 'application/json' `
            -Body (@{ code = $code } | ConvertTo-Json) -TimeoutSec 60
    } catch {
        Write-Host "`nRecovery code rejected (HTTP $($_.Exception.Response.StatusCode.value__))." -ForegroundColor Red
        Write-Host "Each code works once. Try a different unused code."
        exit 1
    } finally { $code = $null }

    $accessToken = $mfa.access_token
    if (-not $accessToken) { Write-Host "No access token returned." -ForegroundColor Red; exit 1 }
    Write-Host "Recovery code accepted." -ForegroundColor Green
}

$headers = @{ Authorization = "Bearer $accessToken" }
Write-Host "Signed in.`n" -ForegroundColor Green

# --- 2. Don't duplicate an existing offline policy --------------------------
$existing = Invoke-RestMethod -Uri "$base/api/v1/monitoring/policies" -Headers $headers -TimeoutSec 60
$already = @($existing | Where-Object {
    $_.scope -eq 'global' -and ($_.checks | Where-Object { $_.type -eq 'offline' })
})
if ($already.Count -gt 0) {
    Write-Host "A global policy with an offline check already exists:" -ForegroundColor Yellow
    $already | ForEach-Object { "  $($_.name)  (id $($_.id), enabled=$($_.enabled))" }
    Write-Host "`nNothing to do. Delete or edit that policy instead of adding a second."
    exit 0
}

# --- 3. Create it -----------------------------------------------------------
# threshold value is SECONDS SINCE last_seen_at: warn at 10 min, critical at 30.
# raise_samples 2 debounces reboots, so a real alarm lands ~15 min after an
# endpoint goes quiet rather than paging on every restart.
$policy = @{
    name        = 'Fleet offline detection'
    scope       = 'global'
    enabled     = $true
    change_note = 'Catch-all offline check so a stalled endpoint alerts instead of going unnoticed.'
    checks      = @(
        @{
            key        = 'endpoint-offline'
            type       = 'offline'
            enabled    = $true
            schedule   = @{ interval_seconds = 300 }
            threshold  = @{ op = 'gt'; warning = 600; critical = 1800 }
            hysteresis = @{ raise_samples = 2; clear_samples = 1 }
        }
    )
} | ConvertTo-Json -Depth 6

try {
    $created = Invoke-RestMethod -Uri "$base/api/v1/monitoring/policies" -Method POST `
        -Headers $headers -ContentType 'application/json' -Body $policy -TimeoutSec 60
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    Write-Host "`nCreate failed (HTTP $code): $($_.Exception.Message)" -ForegroundColor Red
    if ($code -eq 403) { Write-Host "Your account needs at least the 'operator' global role." }
    if ($code -eq 409) { Write-Host "A policy for this scope already exists, or the policy limit is reached." }
    exit 1
}

Write-Host "Created policy '$($created.name)' (id $($created.id))" -ForegroundColor Green
Write-Host "  scope:   $($created.scope)"
$created.checks | ForEach-Object {
    Write-Host "  check:   $($_.key) / $($_.type)  every $($_.schedule.interval_seconds)s"
    Write-Host "  warn >:  $($_.threshold.warning)s since last heartbeat"
    Write-Host "  crit >:  $($_.threshold.critical)s since last heartbeat"
}

Write-Host "`nWhat happens next:" -ForegroundColor Cyan
Write-Host "  The offline sweeper evaluates this on its next pass. Any endpoint"
Write-Host "  already past the threshold becomes critical and queues an alert,"
Write-Host "  so you should receive mail within a few minutes."
Write-Host "`nConfirm delivery config separately with:"
Write-Host "  GET $base/api/v1/monitoring/email-alerts/status"
