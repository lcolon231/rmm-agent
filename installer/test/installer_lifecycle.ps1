# SPDX-License-Identifier: AGPL-3.0-only
#
# Behavioral installer lifecycle test (issue #288).
#
# The contract tests in this folder only grep NodeLinkAgent.iss. This script
# runs two compiled, differently stamped installers and asserts what they do:
#
#   1. sidecar only     - a nodelink-enroll.token beside Setup.exe supplies the
#                         token (first line, trimmed) with no /TOKEN argument.
#   2. /TOKEN + sidecar - the explicit argument wins over the sidecar.
#   3. upgrade in place - with an enrolled (token-free config + protected
#                         identity) install present, the newer installer runs
#                         with no token, leaves identity.json and config.json
#                         byte-identical, replaces the binary, and the service
#                         restarts on the preserved identity.
#   4. uninstall        - removes the service and the runtime files.
#
# Both installers must be compiled with /DProductionServerURL pointing at an
# unreachable host (CI uses https://nodelink-ci.invalid) so the service that
# starts here never contacts a real server.
#
# Run elevated:
#   pwsh -File installer/test/installer_lifecycle.ps1 -SetupV1 <old.exe> `
#        -SetupV2 <new.exe> -V2Version <new version> -ServerURL <url>
#
# Exits non-zero on the first failed assertion.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $SetupV1,
    [Parameter(Mandatory = $true)] [string] $SetupV2,
    [Parameter(Mandatory = $true)] [string] $V2Version,
    [Parameter(Mandatory = $true)] [string] $ServerURL
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$ServiceName = 'NodeLinkAgent'
$SidecarName = 'nodelink-enroll.token'
$Utf8NoBom = New-Object System.Text.UTF8Encoding $false

$tempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$work = Join-Path $tempRoot 'nodelink-installer-lifecycle'
$dir = Join-Path $work 'app'
$configPath = Join-Path $dir 'config.json'
$identityPath = Join-Path $dir 'identity.json'
$agentLog = Join-Path $env:ProgramData 'NodeLink\logs\rmm-agent.log'

function Fail([string] $Message) {
    Write-Host "INSTALLER LIFECYCLE FAIL: $Message" -ForegroundColor Red
    if (Test-Path $agentLog) {
        Write-Host '--- agent log (tail) ---'
        Get-Content $agentLog -Tail 40 | ForEach-Object { Write-Host $_ }
    }
    exit 1
}

function Invoke-Setup([string] $Setup, [string[]] $Extra = @()) {
    $log = Join-Path $work ("setup-{0}.log" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
    $argList = @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', "/DIR=`"$dir`"", "/LOG=`"$log`"") + $Extra
    Write-Host "> $(Split-Path -Leaf $Setup) $($argList -join ' ')"
    $p = Start-Process -FilePath $Setup -ArgumentList $argList -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        if (Test-Path $log) { Get-Content $log -Tail 40 | ForEach-Object { Write-Host $_ } }
        Fail "installer exited $($p.ExitCode)"
    }
}

function Read-Config {
    if (-not (Test-Path $configPath)) { Fail 'config.json not written' }
    return Get-Content -Raw $configPath | ConvertFrom-Json
}

function Assert-FreshConfig([string] $ExpectedToken) {
    $config = Read-Config
    if ($config.server_url -ne $ServerURL) { Fail "server_url is '$($config.server_url)', expected '$ServerURL'" }
    if ($config.enrollment_token -ne $ExpectedToken) {
        # Never echo a token value that came from the wrong source; the name is enough.
        Fail "enrollment_token does not match the expected source ($ExpectedToken)"
    }
    if (Test-Path $identityPath) { Fail 'identity.json exists after a fresh install against an unreachable server' }
    Write-Host "  ok: config.json uses $ServerURL and token '$ExpectedToken'"
}

function Assert-Running {
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $svc) { Fail 'service not registered by installer' }
    if ($svc.Status -ne 'Running') { Fail "service is $($svc.Status), expected Running" }
    Write-Host '  ok: service is Running'
}

# Writes identity.json as the installed service would after enrolling: the
# versioned envelope with a DPAPI user-scope payload. It must be protected as
# LocalSystem (the service account), so it is produced by a one-shot SYSTEM
# scheduled task; an identity protected as the runner account would make the
# upgraded service exit on start. The payload is fixture data, not a credential.
function Write-ServiceIdentity([string] $AgentId) {
    # Ed25519 SubjectPublicKeyInfo: fixed DER prefix + 32 key bytes. The agent
    # only parses this key at startup; any 32 bytes form a valid public key.
    $key = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    $der = [byte[]](@(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00) + $key)
    $pem = "-----BEGIN PUBLIC KEY-----`n$([Convert]::ToBase64String($der))`n-----END PUBLIC KEY-----`n"

    $payloadPath = Join-Path $work 'identity-payload.json'
    $payload = [ordered]@{
        agent_id           = $AgentId
        agent_token        = 'ci-upgrade-fixture'
        command_public_key = $pem
        heartbeat_seconds  = 60
        server_url         = $ServerURL
    } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($payloadPath, $payload, $Utf8NoBom)

    $helper = Join-Path $work 'protect-identity.ps1'
    @'
param([string] $PayloadPath, [string] $OutPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$plain = [IO.File]::ReadAllBytes($PayloadPath)
$blob = [Security.Cryptography.ProtectedData]::Protect(
    $plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
$envelope = [ordered]@{
    format     = 'nodelink-agent-identity'
    version    = 1
    protection = 'dpapi'
    data       = [Convert]::ToBase64String($blob)
} | ConvertTo-Json
[IO.File]::WriteAllText("$OutPath.tmp", $envelope, (New-Object System.Text.UTF8Encoding $false))
Move-Item -Force "$OutPath.tmp" $OutPath
'@ | Set-Content -Path $helper -Encoding ascii

    $task = 'NodeLinkCiProtectIdentity'
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
        "-NoProfile -ExecutionPolicy Bypass -File `"$helper`" -PayloadPath `"$payloadPath`" -OutPath `"$identityPath`"")
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal | Out-Null
    try {
        Start-ScheduledTask -TaskName $task
        $deadline = (Get-Date).AddSeconds(60)
        while (-not (Test-Path $identityPath)) {
            if ((Get-Date) -gt $deadline) {
                $result = (Get-ScheduledTaskInfo -TaskName $task).LastTaskResult
                Fail "SYSTEM task did not write identity.json (last result $result)"
            }
            Start-Sleep -Milliseconds 500
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Force $payloadPath, $helper -ErrorAction SilentlyContinue
    }
}

# Clean slate: a leftover service or install dir would poison the test.
if (Test-Path (Join-Path $dir 'unins000.exe')) {
    Start-Process -FilePath (Join-Path $dir 'unins000.exe') -Wait -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
}
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force $work | Out-Null
if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Fail 'a NodeLinkAgent service already exists; run on a clean machine'
}

# Personalized download: Setup.exe and the sidecar in the same folder ({src}).
$bundle = Join-Path $work 'personalized-download'
New-Item -ItemType Directory -Force $bundle | Out-Null
$bundledSetup = Join-Path $bundle (Split-Path -Leaf $SetupV1)
Copy-Item $SetupV1 $bundledSetup
# Only the first line counts and it is trimmed, so pad it and add a second line.
[IO.File]::WriteAllText((Join-Path $bundle $SidecarName), "  ci-sidecar-token  `r`nci-ignored-second-line`r`n", $Utf8NoBom)

Write-Host "`n== fresh install, token from sidecar only =="
Invoke-Setup $bundledSetup
Assert-FreshConfig 'ci-sidecar-token'
Assert-Running

Write-Host "`n== fresh install, /TOKEN overrides the sidecar =="
Invoke-Setup $bundledSetup @('/TOKEN=ci-arg-token')
Assert-FreshConfig 'ci-arg-token'
Assert-Running

Write-Host "`n== simulate a completed enrollment =="
# What the service leaves behind after enrolling: the token is cleared from
# config.json and the identity is DPAPI-protected under LocalSystem.
$p = Start-Process -FilePath (Join-Path $dir 'rmm-agent.exe') -ArgumentList 'stop' -Wait -PassThru -NoNewWindow
if ($p.ExitCode -ne 0) { Fail "agent stop exited $($p.ExitCode)" }
[IO.File]::WriteAllText($configPath, "{`r`n  `"server_url`": `"$ServerURL`"`r`n}`r`n", $Utf8NoBom)
$agentId = "ci-upgrade-$([guid]::NewGuid().ToString('N').Substring(0, 12))"
Write-ServiceIdentity $agentId
$before = @{
    config   = (Get-FileHash $configPath -Algorithm SHA256).Hash
    identity = (Get-FileHash $identityPath -Algorithm SHA256).Hash
}
Write-Host "  ok: enrolled state for agent $agentId"

Write-Host "`n== upgrade in place with a newer build, no token =="
$v2Source = Split-Path -Parent (Resolve-Path $SetupV2)
if (Test-Path (Join-Path $v2Source $SidecarName)) { Fail "unexpected $SidecarName beside $SetupV2" }
Invoke-Setup $SetupV2
foreach ($name in 'config', 'identity') {
    $path = if ($name -eq 'config') { $configPath } else { $identityPath }
    if (-not (Test-Path $path)) { Fail "$name file removed by the upgrade" }
    if ((Get-FileHash $path -Algorithm SHA256).Hash -ne $before[$name]) { Fail "$name file changed during the upgrade" }
}
Write-Host '  ok: identity.json and config.json are byte-identical'
$p = Start-Process -FilePath (Join-Path $dir 'rmm-agent.exe') -ArgumentList "version -expect $V2Version" -Wait -PassThru -NoNewWindow
if ($p.ExitCode -ne 0) { Fail "installed binary does not report $V2Version" }
Write-Host "  ok: installed binary reports $V2Version"

# The service must come up on the preserved identity, not exit on it.
$deadline = (Get-Date).AddSeconds(30)
while (-not ((Test-Path $agentLog) -and (Select-String -Path $agentLog -SimpleMatch "loaded existing identity: agent $agentId" -Quiet))) {
    if ((Get-Date) -gt $deadline) { Fail 'upgraded service never loaded the preserved identity' }
    Start-Sleep -Seconds 1
}
Start-Sleep -Seconds 3
Assert-Running
Write-Host '  ok: upgraded service loaded the preserved identity'

Write-Host "`n== silent uninstall =="
$unins = Join-Path $dir 'unins000.exe'
if (-not (Test-Path $unins)) { Fail "uninstaller missing at $unins" }
$u = Start-Process -FilePath $unins -Wait -PassThru -ArgumentList '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART'
if ($u.ExitCode -ne 0) { Fail "uninstaller exited $($u.ExitCode)" }
Start-Sleep -Seconds 2
if ($null -ne (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { Fail 'service still present after uninstall' }
foreach ($path in $configPath, $identityPath) {
    if (Test-Path $path) { Fail "$(Split-Path -Leaf $path) left behind after uninstall" }
}
Write-Host '  ok: service and runtime files removed'

Write-Host "`nINSTALLER LIFECYCLE OK" -ForegroundColor Green
