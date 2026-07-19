# SPDX-License-Identifier: AGPL-3.0-only
#
# Windows service lifecycle test for the NodeLink agent (issue #23).
#
# Drives the agent's own CLI verbs (install/start/stop/uninstall) and asserts
# the Windows Service Control Manager state after each, covering: install +
# auto-start registration, start -> Running, stop -> Stopped, restart, the
# "install refuses when already installed" contract, uninstall -> absent, and
# idempotent uninstall. No RMM server is required: enrollment fails against the
# unreachable test URL and the service stays Running (the runtime retries with
# backoff), which is exactly the resilience this proves.
#
# Run from an elevated shell:  pwsh -File agent/test/service_lifecycle.ps1 -Exe <path-to-rmm-agent.exe>
#
# Exits non-zero on the first failed assertion.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Exe
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'NodeLinkAgent'

function Fail([string] $Message) {
    Write-Host "LIFECYCLE FAIL: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Agent([string] $ArgLine, [switch] $AllowFailure) {
    Write-Host "> rmm-agent $ArgLine"
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgLine -NoNewWindow -Wait -PassThru
    if (-not $AllowFailure -and $p.ExitCode -ne 0) {
        Fail "'$ArgLine' exited $($p.ExitCode)"
    }
    return $p.ExitCode
}

function Get-ServiceOrNull {
    return Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Assert-State([string] $Expected) {
    $svc = Get-ServiceOrNull
    if ($null -eq $svc) { Fail "service not present, expected state $Expected" }
    if ($svc.Status -ne $Expected) { Fail "service state $($svc.Status), expected $Expected" }
    Write-Host "  ok: service is $Expected"
}

function Assert-Absent {
    if ($null -ne (Get-ServiceOrNull)) { Fail 'service still present, expected absent' }
    Write-Host '  ok: service is absent'
}

# Clean slate: a leftover service from a previous run would poison the test.
Invoke-Agent 'uninstall' -AllowFailure | Out-Null
Assert-Absent

# A minimal config beside the binary. server_url is required by config.Load;
# the address is intentionally unreachable — we are testing service lifecycle,
# not enrollment.
$workDir = Split-Path -Parent $Exe
$configPath = Join-Path $workDir 'config.json'
@'
{
  "server_url": "https://nodelink-ci.invalid",
  "enrollment_token": "ci-lifecycle-token"
}
'@ | Set-Content -Path $configPath -Encoding ascii

Write-Host "`n== install =="
Invoke-Agent "install -config `"$configPath`"" | Out-Null
$svc = Get-ServiceOrNull
if ($null -eq $svc) { Fail 'service not registered after install' }
if ($svc.StartType -ne 'Automatic') { Fail "start type $($svc.StartType), expected Automatic" }
Write-Host '  ok: registered with Automatic start'

Write-Host "`n== install again (must refuse) =="
$code = Invoke-Agent "install -config `"$configPath`"" -AllowFailure
if ($code -eq 0) { Fail 'second install unexpectedly succeeded; must refuse when already installed' }
Write-Host "  ok: refused with exit $code"

Write-Host "`n== start =="
Invoke-Agent 'start' | Out-Null
Assert-State 'Running'

Write-Host "`n== stop =="
Invoke-Agent 'stop' | Out-Null
Assert-State 'Stopped'

Write-Host "`n== restart =="
Invoke-Agent 'start' | Out-Null
Assert-State 'Running'

Write-Host "`n== uninstall (stops a running service) =="
Invoke-Agent 'uninstall' | Out-Null
Assert-Absent

Write-Host "`n== uninstall again (idempotent) =="
Invoke-Agent 'uninstall' | Out-Null
Assert-Absent

Write-Host "`nLIFECYCLE OK" -ForegroundColor Green
