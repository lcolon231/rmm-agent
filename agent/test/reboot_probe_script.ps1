# SPDX-License-Identifier: AGPL-3.0-only
#
# Behavioral test for the reboot-source probe script (issue #231).
#
# The Windows probe embeds a PowerShell script as a Go string literal. Nothing
# else executes it: `go test` on Windows never calls RebootPending because that
# needs a real registry, so without this test the script's own logic ships
# unexercised and a defect in it surfaces only on an endpoint.
#
# This extracts the exact script text from probe_windows.go, parses it with the
# PowerShell parser, then runs it against stubbed registry state. Test-Path and
# Get-ItemProperty are shadowed by functions in the same scope, so the script
# under test is byte-identical to the shipped one -- only the registry beneath
# it is simulated. It therefore runs anywhere PowerShell does, Linux included.
#
# Run:  pwsh -File agent/test/reboot_probe_script.ps1
#
# Exits non-zero on the first failed assertion.

param(
    [string]$Source = (Join-Path $PSScriptRoot '..' 'internal' 'monitoring' 'probe_windows.go')
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $Source)) { throw "probe source not found: $Source" }

# Concatenate the raw-string chunks of the script literal, skipping the Go line
# comments between them and stopping at the closing backtick of the last chunk.
$go = Get-Content -Raw $Source
$body = $go.Substring($go.IndexOf('func (platformProbe) RebootPending'))
$body = $body.Substring(0, $body.IndexOf('out, err := powerShell'))
$chunks = [regex]::Matches($body, '`([^`]*)`') | ForEach-Object { $_.Groups[1].Value }
if ($chunks.Count -lt 2) { throw "could not extract the probe script from $Source" }
$script = -join $chunks

$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($script, [ref]$null, [ref]$errors)
if ($errors) {
    $errors | ForEach-Object { Write-Error ("probe script parse error: " + $_.Message) }
    exit 1
}

$prelude = @'
function Test-Path { [CmdletBinding()] param([Parameter(Position=0)]$Path)
    if ($Path -like '*Component Based Servicing*') { return $global:CBS }
    if ($Path -like '*WindowsUpdate*') { return $global:WU }
    return $false }
function Get-ItemProperty { [CmdletBinding()] param([Parameter(Position=0)]$Path, $Name)
    if ($null -eq $global:PFR) { return $null }
    if ($global:UNREADABLE) {
        # A registry value the provider cannot read back. A property getter
        # that fails yields $null instead of raising, which is why the script
        # may not rely on catch alone to report the count as unknown.
        $o = New-Object psobject
        Add-Member -InputObject $o -MemberType ScriptProperty -Name PendingFileRenameOperations -Value { throw 'registry read failed' }
        return $o }
    return [pscustomobject]@{ PendingFileRenameOperations = $global:PFR } }
'@

function Invoke-Probe {
    param([bool]$Cbs, [bool]$Wu, $Pfr, [bool]$Unreadable = $false)
    $global:CBS = $Cbs; $global:WU = $Wu; $global:PFR = $Pfr; $global:UNREADABLE = $Unreadable
    $block = [scriptblock]::Create($prelude + "`n" + $script)
    return ((& $block) -split "`n") -join '|'
}

$failures = 0
function Assert-Probe {
    param([string]$Name, [string]$Expected, [string]$Actual)
    if ($Actual -ne $Expected) {
        Write-Host "FAIL $Name`n  expected: $Expected`n  actual:   $Actual"
        $script:failures++
    } else {
        Write-Host "ok   $Name -> $Actual"
    }
}

# Each source is reported independently, and only WindowsUpdate means an
# installed update is waiting on a restart.
Assert-Probe 'no source set'      'false|false|false|-1' (Invoke-Probe $false $false $null)
Assert-Probe 'servicing only'     'true|false|false|-1'  (Invoke-Probe $true  $false $null)
Assert-Probe 'windows update only' 'false|true|false|-1' (Invoke-Probe $false $true  $null)
Assert-Probe 'all three set'      'true|true|true|1'     (Invoke-Probe $true  $true  @('C:\a.tmp','C:\a.dll'))

# The count walks source/destination pairs and ignores a trailing terminator.
Assert-Probe 'one queued rename'  'false|false|true|1' (Invoke-Probe $false $false @('C:\x.tmp','C:\x.dll'))
Assert-Probe 'two queued renames' 'false|false|true|2' (Invoke-Probe $false $false @('C:\Users\alice\a.tmp','C:\Users\alice\a.dll','\??\C:\b.tmp',''))
Assert-Probe 'empty value'        'false|false|true|0' (Invoke-Probe $false $false @())

# A count the provider cannot produce must be unknown (-1), never zero: zero
# reads as "no renames queued" and would be a false statement about the
# endpoint. The agent omits the key entirely for -1.
Assert-Probe 'unreadable value'   'false|false|true|-1' (Invoke-Probe $false $false @('x') $true)

# No code path may emit a file path: those routinely contain user names and
# result detail is meant to stay safe to forward to email and webhooks.
$withPaths = Invoke-Probe $true $true @('C:\Users\alice\AppData\Local\Temp\x.tmp','C:\Windows\System32\x.dll')
foreach ($needle in @('C:', '\', 'Users', 'alice', 'Temp')) {
    if ($withPaths.Contains($needle)) {
        Write-Host "FAIL probe output leaked path fragment '$needle': $withPaths"
        $failures++
    }
}
if (-not $withPaths.Contains('Users')) { Write-Host "ok   no path fragment in output -> $withPaths" }

if ($failures -gt 0) { Write-Host "`n$failures assertion(s) failed"; exit 1 }
Write-Host "`nreboot probe script: all assertions passed"
