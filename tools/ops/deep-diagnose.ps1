# Why did no alert open for agents that are active and long past the offline
# threshold? Checks policy resolution and check-result writing per agent.
#
# Caches the access token in this folder so repeated runs do not spend another
# recovery code. Delete nodelink-token.txt when you are done.

param(
    [string]$BaseUrl = 'https://nodelink-backend-733e.onrender.com'
)

$ErrorActionPreference = 'Stop'
$base = $BaseUrl

# The cached bearer deliberately lives outside the repository. It is a live
# operator credential; never let it land somewhere that can be committed.
$cacheDir = Join-Path $env:LOCALAPPDATA 'NodeLink'
if (-not (Test-Path $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
$tokenFile = Join-Path $cacheDir 'operator-token.txt'

function Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }

# --- Reuse a cached token if it still works ---------------------------------
$accessToken = $null
if (Test-Path $tokenFile) {
    $cached = (Get-Content $tokenFile -Raw).Trim()
    try {
        Invoke-RestMethod -Uri "$base/api/v1/agents" -Headers @{ Authorization = "Bearer $cached" } -TimeoutSec 30 | Out-Null
        $accessToken = $cached
        Write-Host "Reusing cached token." -ForegroundColor Green
    } catch { Write-Host "Cached token expired; signing in again." -ForegroundColor Yellow }
}

if (-not $accessToken) {
    $email = Read-Host "Operator email"
    $secure = Read-Host "Password" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    try {
        $login = Invoke-RestMethod -Uri "$base/api/v1/auth/login" -Method POST `
            -ContentType 'application/json' `
            -Body (@{ email = $email; password = $plain } | ConvertTo-Json) -TimeoutSec 60
    } catch { Write-Host "Login failed." -ForegroundColor Red; exit 1 } finally { $plain = $null }

    $accessToken = $login.access_token
    if (-not $accessToken) {
        $code = Read-Host "Recovery code"
        try {
            $mfa = Invoke-RestMethod -Uri "$base/api/v1/auth/mfa/login/recovery-code" -Method POST `
                -Headers @{ Authorization = "Bearer $($login.mfa_token)" } `
                -ContentType 'application/json' `
                -Body (@{ code = $code } | ConvertTo-Json) -TimeoutSec 60
        } catch { Write-Host "Recovery code rejected." -ForegroundColor Red; exit 1 } finally { $code = $null }
        $accessToken = $mfa.access_token
    }
    Set-Content -Path $tokenFile -Value $accessToken -Encoding utf8
    Write-Host "Signed in; token cached at $tokenFile" -ForegroundColor Green
}
$h = @{ Authorization = "Bearer $accessToken" }

# --- Per-agent: does the policy resolve, and are results being written? -----
$agents = Invoke-RestMethod -Uri "$base/api/v1/agents" -Headers $h -TimeoutSec 60
foreach ($a in $agents) {
    if ($a.trust_state -ne 'active') { continue }

    Section "$($a.hostname)  [$($a.id)]"
    $mins = 'never'
    if ($a.last_seen_at) {
        $mins = [math]::Round(((Get-Date).ToUniversalTime() - [datetime]$a.last_seen_at).TotalMinutes)
    }
    Write-Host "  last_seen: $mins min ago  (critical threshold is 30 min)"

    # Does the global offline policy actually reach this agent?
    try {
        $eff = Invoke-RestMethod -Uri "$base/api/v1/agents/$($a.id)/monitoring/effective-policy" -Headers $h -TimeoutSec 60
        $checks = $eff.checks
        if (-not $checks) { $checks = $eff }
        $found = $false
        @($checks) | ForEach-Object {
            if ($_.key -or $_.type) {
                Write-Host "  effective check: key=$($_.key) type=$($_.type) enabled=$($_.enabled) interval=$($_.schedule.interval_seconds)"
                if ($_.type -eq 'offline') { $found = $true }
            }
        }
        if (-not $found) {
            Write-Host "  NO offline check resolves for this agent" -ForegroundColor Red
            Write-Host "  -> the global policy is not reaching it; nothing will ever alarm"
        }
    } catch {
        Write-Host "  effective-policy read failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # Have any check results actually been written?
    try {
        $res = Invoke-RestMethod -Uri "$base/api/v1/agents/$($a.id)/monitoring/results" -Headers $h -TimeoutSec 60
        $items = $res
        if ($res.items) { $items = $res.items }
        if (-not $items -or @($items).Count -eq 0) {
            Write-Host "  NO check results written yet" -ForegroundColor Red
            Write-Host "  -> the sweeper is not evaluating this agent"
        } else {
            Write-Host "  recent check results:"
            @($items) | Select-Object -First 5 | ForEach-Object {
                Write-Host ("    {0,-20} {1,-9} value={2} at {3}" -f $_.check_key, $_.status, $_.value, $_.evaluated_at)
            }
        }
    } catch {
        Write-Host "  results read failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Write-Host "`nHow to read this:" -ForegroundColor Cyan
Write-Host "  no offline check resolves  -> policy scope/assignment problem"
Write-Host "  check resolves, no results -> sweeper not running or not reaching this agent"
Write-Host "  results ok + status ok     -> threshold wrong (value under 1800s)"
Write-Host "  results critical, no alert -> alert creation is the broken link"
