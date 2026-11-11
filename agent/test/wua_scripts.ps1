# SPDX-License-Identifier: AGPL-3.0-only
#
# Behavioral test for the Windows Update Agent scan and install scripts
# (issue #279).
#
# Both scripts are embedded in the agent as Go string literals (psScript in
# scan_windows.go, psInstallScript in install_windows.go). go test only covers
# the Go-side parsers (BuildSection, assembleInstallResult, extractPSJSON), so
# a defect in the scripts themselves would otherwise surface only on an
# endpoint.
#
# This extracts the exact script text from the Go sources, parses it with the
# PowerShell parser, then runs it in a child pwsh process with New-Object
# shadowed by a function that returns stub WUA COM objects
# (Microsoft.Update.SystemInfo / Session / UpdateColl). The scripts under test
# are byte-identical to the shipped ones; only the Windows Update service under
# them is simulated, so this runs anywhere PowerShell does, Linux included.
#
# Each case runs in its own process because the install script calls `exit`,
# exactly as it does under powershell.exe -EncodedCommand in production.
#
# The emitted JSON is checked against the keys the Go side accepts: rawScan's
# json tags, the missingFields / installedFields allowlists BuildSection
# applies, and the InstallResult / UpdateOutcome json tags that
# assembleInstallResult and InstallWithRetry consume.
#
# Run:  pwsh -File agent/test/wua_scripts.ps1
#
# Exits non-zero if any assertion fails.

param(
    [string]$PatchingDir = (Join-Path $PSScriptRoot '..' 'internal' 'patching')
)

$ErrorActionPreference = 'Stop'

$scanSource    = Join-Path $PatchingDir 'scan_windows.go'
$installSource = Join-Path $PatchingDir 'install_windows.go'
$scanGo        = Join-Path $PatchingDir 'scan.go'
$installGo     = Join-Path $PatchingDir 'install.go'
foreach ($p in @($scanSource, $installSource, $scanGo, $installGo)) {
    if (-not (Test-Path $p)) { throw "source not found: $p" }
}

# --- extract the scripts and the Go-side contracts ---------------------------

function Get-GoRawString([string]$Path, [string]$Const) {
    $go = Get-Content -Raw $Path
    $m = [regex]::Match($go, "const $Const = ``([^``]*)``")
    if (-not $m.Success) { throw "could not extract $Const from $Path" }
    return $m.Groups[1].Value
}

function Get-GoStringList([string]$Path, [string]$Var) {
    $go = Get-Content -Raw $Path
    $m = [regex]::Match($go, "var $Var = \[\]string\{([^}]*)\}")
    if (-not $m.Success) { throw "could not extract $Var from $Path" }
    return @([regex]::Matches($m.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
}

function Get-GoJsonTags([string]$Path, [string]$Type) {
    $go = Get-Content -Raw $Path
    $m = [regex]::Match($go, "type $Type struct \{([^}]*)\}")
    if (-not $m.Success) { throw "could not extract struct $Type from $Path" }
    return @([regex]::Matches($m.Groups[1].Value, 'json:"([^",]+)') | ForEach-Object { $_.Groups[1].Value })
}

$scanScript    = Get-GoRawString $scanSource 'psScript'
$installScript = Get-GoRawString $installSource 'psInstallScript'

$rawScanKeys     = Get-GoJsonTags $scanSource 'rawScan'
$missingFields   = Get-GoStringList $scanGo 'missingFields'
$installedFields = Get-GoStringList $scanGo 'installedFields'
$installKeys     = Get-GoJsonTags $installGo 'InstallResult'
$outcomeKeys     = Get-GoJsonTags $installGo 'UpdateOutcome'

foreach ($pair in @(@('scan', $scanScript), @('install', $installScript))) {
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($pair[1], [ref]$null, [ref]$errors)
    if ($errors) {
        $errors | ForEach-Object { Write-Host ("FAIL $($pair[0]) script parse error: " + $_.Message) }
        exit 1
    }
}

# --- stub WUA COM objects -------------------------------------------------------
#
# A case defines $Fake before this prelude runs:
#   SystemReboot   bool, or $null to make Microsoft.Update.SystemInfo fail
#   SessionHResult int HRESULT to make Microsoft.Update.Session creation fail
#   SearchHResult  int HRESULT to make IUpdateSearcher.Search fail
#   Updates        hashtables: Title KB UpdateID Severity Class Product Url
#                  LDC Reboot Downloaded
#   History        hashtables: UpdateID Rev Title Description Date AppID Url
#                  ResultCode HResult Operation (newest first, as WUA returns)
#   Install        UpdateID -> @{ ResultCode; HResult; Reboot }
#   InstallReboot  IInstallationResult.RebootRequired

$prelude = @'
function New-Coll([object[]]$Items) {
    $l = [System.Collections.ArrayList]::new()
    foreach ($i in $Items) { [void]$l.Add($i) }
    return ,$l
}

function New-FakeUpdate($d) {
    $cats = @()
    if ($d.Class)   { $cats += [pscustomobject]@{ Type = 'UpdateClassification'; Name = $d.Class } }
    if ($d.Product) { $cats += [pscustomobject]@{ Type = 'Product'; Name = $d.Product } }
    $kbs = @(); if ($d.KB) { $kbs = @($d.KB) }
    $urls = @(); if ($d.Url) { $urls = @($d.Url) }
    $u = [pscustomobject]@{
        Title                    = $d.Title
        KBArticleIDs             = (New-Coll $kbs)
        Identity                 = [pscustomobject]@{ UpdateID = $d.UpdateID; RevisionNumber = 1 }
        Categories               = (New-Coll $cats)
        MoreInfoUrls             = (New-Coll $urls)
        LastDeploymentChangeTime = $d.LDC
        MsrcSeverity             = $d.Severity
        InstallationBehavior     = [pscustomobject]@{ RebootBehavior = [int]$d.Reboot }
        IsDownloaded             = [bool]$d.Downloaded
        EulaAccepted             = $false
    }
    $u | Add-Member ScriptMethod AcceptEula { $this.EulaAccepted = $true }
    return $u
}

function New-FakeHistory($d) {
    return [pscustomobject]@{
        UpdateIdentity      = [pscustomobject]@{ UpdateID = $d.UpdateID; RevisionNumber = $d.Rev }
        Title               = $d.Title
        Description         = $d.Description
        Date                = $d.Date
        ClientApplicationID = $d.AppID
        SupportUrl          = $d.Url
        ResultCode          = $d.ResultCode
        HResult             = $d.HResult
        Operation           = $d.Operation
    }
}

function New-FakeSession {
    $s = [pscustomobject]@{}
    $s | Add-Member ScriptMethod CreateUpdateSearcher {
        $searcher = [pscustomobject]@{}
        $searcher | Add-Member ScriptMethod Search {
            param($criteria)
            if ($criteria -ne 'IsInstalled=0 and IsHidden=0') { throw "unexpected search criteria: $criteria" }
            if ($null -ne $Fake.SearchHResult) {
                throw [System.Runtime.InteropServices.COMException]::new('search failed', [int]$Fake.SearchHResult)
            }
            $updates = @(); foreach ($d in @($Fake.Updates)) { if ($d) { $updates += New-FakeUpdate $d } }
            return [pscustomobject]@{ Updates = (New-Coll $updates) }
        }
        $searcher | Add-Member ScriptMethod GetTotalHistoryCount { return @($Fake.History | Where-Object { $_ }).Count }
        $searcher | Add-Member ScriptMethod QueryHistory {
            param($start, $count)
            $rows = @(); foreach ($d in @($Fake.History)) { if ($d) { $rows += New-FakeHistory $d } }
            return ,(New-Coll ($rows | Select-Object -Skip $start -First $count))
        }
        return $searcher
    }
    $s | Add-Member ScriptMethod CreateUpdateDownloader {
        $dl = [pscustomobject]@{ Updates = $null }
        $dl | Add-Member ScriptMethod Download {
            $global:Downloaded = @($this.Updates | ForEach-Object { $_.Identity.UpdateID })
            return [pscustomobject]@{ HResult = 0; ResultCode = 2 }
        }
        return $dl
    }
    $s | Add-Member ScriptMethod CreateUpdateInstaller {
        $inst = [pscustomobject]@{ Updates = $null }
        $inst | Add-Member ScriptMethod Install {
            $ids = @($this.Updates | ForEach-Object { $_.Identity.UpdateID })
            $global:Installed = $ids
            foreach ($u in $this.Updates) {
                if (-not $u.EulaAccepted) { throw "installed $($u.Identity.UpdateID) without accepting its EULA" }
            }
            $res = [pscustomobject]@{ RebootRequired = [bool]$Fake.InstallReboot; Ids = $ids }
            $res | Add-Member ScriptMethod GetUpdateResult {
                param($i)
                $r = $Fake.Install[$this.Ids[$i]]
                if (-not $r) { $r = @{ ResultCode = 2; HResult = 0; Reboot = $false } }
                return [pscustomobject]@{ ResultCode = $r.ResultCode; HResult = $r.HResult; RebootRequired = [bool]$r.Reboot }
            }
            return $res
        }
        return $inst
    }
    return $s
}

function New-Object {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$TypeName, [string]$ComObject)
    switch ($ComObject) {
        'Microsoft.Update.SystemInfo' {
            if ($null -eq $Fake.SystemReboot) { throw [System.Runtime.InteropServices.COMException]::new('no system info', -2147221164) }
            return [pscustomobject]@{ RebootRequired = $Fake.SystemReboot }
        }
        'Microsoft.Update.Session' {
            if ($null -ne $Fake.SessionHResult) {
                throw [System.Runtime.InteropServices.COMException]::new('session unavailable', [int]$Fake.SessionHResult)
            }
            return New-FakeSession
        }
        'Microsoft.Update.UpdateColl' { return ,(New-Coll @()) }
        '' { return Microsoft.PowerShell.Utility\New-Object -TypeName $TypeName }
        default { throw "unexpected COM object: $ComObject" }
    }
}
'@

$pwsh = (Get-Process -Id $PID).Path

# Runs one case in a child process the way the agent does (-EncodedCommand is
# the base64 of the UTF-16LE script text) and returns the decoded JSON plus
# its raw line. Mirrors extractPSJSON: the payload is the last line that is a
# JSON object, so stray success-stream output does not hide it.
function Invoke-Case([string]$FakeDef, [string]$Body) {
    $text = $FakeDef + "`n" + $prelude + "`n" + $Body
    $enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($text))
    $out = & $pwsh -NoProfile -NonInteractive -EncodedCommand $enc
    if ($LASTEXITCODE -ne 0) { throw "script exited $LASTEXITCODE`n$($out -join "`n")" }
    $lines = @($out | ForEach-Object { "$_".Trim() } | Where-Object { $_.StartsWith('{') })
    if ($lines.Count -eq 0) { throw "no JSON object on stdout:`n$($out -join "`n")" }
    $raw = $lines[-1]
    $noise = @($out | Where-Object { "$_".Trim() -and "$_".Trim() -ne $raw })
    return [pscustomobject]@{ Json = ($raw | ConvertFrom-Json -AsHashtable); Raw = $raw; Noise = $noise }
}

# The install command line prefix, built the same way Install() builds it.
function Get-InstallPrefix([bool]$All, [string[]]$KBs, [string[]]$IDs) {
    $lit = { param($v) if (-not $v -or $v.Count -eq 0) { '@()' } else { '@(' + (($v | ForEach-Object { "'$_'" }) -join ',') + ')' } }
    $allLit = if ($All) { 'true' } else { 'false' }
    return ('$InstallAll = ${0}; $TargetKBs = {1}; $TargetUpdateIDs = {2};' -f $allLit, (& $lit $KBs), (& $lit $IDs))
}

# --- assertions ---------------------------------------------------------------

$failures = 0
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { Write-Host "ok   $Name" }
    else { Write-Host "FAIL $Name $Detail"; $script:failures++ }
}
function CheckEq([string]$Name, $Expected, $Actual) {
    $e = ConvertTo-Json -InputObject $Expected -Compress -Depth 5
    $a = ConvertTo-Json -InputObject $Actual -Compress -Depth 5
    Check $Name ($e -eq $a) "`n  expected: $e`n  actual:   $a"
}
# A key Go's decoder would drop or the server would reject (extra="forbid").
function CheckKeys([string]$Name, $Row, [string[]]$Allowed) {
    $extra = @($Row.Keys | Where-Object { $Allowed -notcontains $_ })
    Check "$Name keys are accepted by Go" ($extra.Count -eq 0) "unexpected: $($extra -join ', ')"
}
# A JSON array, not a scalar or object: Go decodes these into slices, and
# PowerShell's habit of unrolling one-element arrays would break that.
function CheckArray([string]$Name, $Value) {
    Check "$Name is a JSON array" ($Value -is [System.Collections.IList]) "got: $($Value | ConvertTo-Json -Compress)"
}
function CheckRaw([string]$Name, $Res, [string]$Fragment) {
    Check $Name ($Res.Raw.Contains($Fragment)) "`n  missing: $Fragment`n  in:      $($Res.Raw)"
}
function CheckNoNoise([string]$Name, $Res) {
    Check "$Name prints nothing but the JSON" ($Res.Noise.Count -eq 0) "extra stdout: $($Res.Noise -join ' | ')"
}

function CheckScanShape([string]$Name, $Res) {
    $j = $Res.Json
    CheckNoNoise $Name $Res
    CheckKeys "$Name top-level" $j $rawScanKeys
    CheckArray "$Name missing" $j.missing
    CheckArray "$Name installed" $j.installed
    foreach ($row in $j.missing) { CheckKeys "$Name missing row" $row $missingFields }
    foreach ($row in $j.installed) { CheckKeys "$Name installed row" $row $installedFields }
}

function CheckInstallShape([string]$Name, $Res) {
    $j = $Res.Json
    CheckNoNoise $Name $Res
    CheckKeys "$Name top-level" $j $installKeys
    foreach ($k in @('status', 'installed_kbs', 'failed_kbs', 'reboot_required', 'message')) {
        Check "$Name has $k" ($j.ContainsKey($k))
    }
    CheckArray "$Name installed_kbs" $j.installed_kbs
    CheckArray "$Name failed_kbs" $j.failed_kbs
    CheckArray "$Name results" $j.results
    foreach ($row in $j.results) { CheckKeys "$Name result row" $row $outcomeKeys }
}

# --- scan ---------------------------------------------------------------------

# Nothing missing, nothing in history.
$r = Invoke-Case '$Fake = @{ SystemReboot = $false; Updates = @(); History = @() }' $scanScript
CheckScanShape 'scan/no updates' $r
CheckEq 'scan/no updates missing' 0 $r.Json.missing.Count
CheckEq 'scan/no updates installed' 0 $r.Json.installed.Count
CheckEq 'scan/no updates reboot_required' $false $r.Json.reboot_required
CheckEq 'scan/no updates error_code' '' $r.Json.error_code
CheckEq 'scan/no updates history_error_code' '' $r.Json.history_error_code

# A KB-identified security update, a KB-less driver update known only by its
# Update ID, and history covering success, dedupe, removal and failure.
$scanFake = @'
$Fake = @{
  SystemReboot = $true
  Updates = @(
    @{ Title = '2026-01 Cumulative Update for Windows 11 (KB5034441)'; KB = '5034441'
       UpdateID = '11111111-1111-1111-1111-111111111111'; Severity = 'Critical'
       Class = 'Security Updates'; Product = 'Windows 11'; Url = 'https://support.microsoft.com/kb/5034441'
       LDC = [datetime]::SpecifyKind([datetime]'2026-01-09T00:00:00', 'Utc'); Reboot = 1; Downloaded = $true },
    @{ Title = 'Contoso - Display - 31.0.1'; KB = $null
       UpdateID = '22222222-2222-2222-2222-222222222222'; Severity = ''
       Class = 'Drivers'; Product = 'Windows 11 Client, version 24H2 and later, Servicing Drivers'
       Url = $null; LDC = $null; Reboot = 0; Downloaded = $false }
  )
  History = @(
    # newest first: the latest operation on 3333 is an uninstall, so it is not installed
    @{ UpdateID = '33333333-3333-3333-3333-333333333333'; Rev = 1; Title = 'Update for Windows (KB5000001)'
       Description = 'd'; Date = [datetime]::SpecifyKind([datetime]'2026-01-05T00:00:00', 'Utc')
       AppID = 'UpdateOrchestrator'; Url = 'u'; ResultCode = 2; HResult = 0; Operation = 2 },
    @{ UpdateID = '44444444-4444-4444-4444-444444444444'; Rev = 200; Title = 'Security Intelligence Update for Microsoft Defender Antivirus - kb2267602 (Version 1.401.1.0)'
       Description = 'Defender'; Date = [datetime]::SpecifyKind([datetime]'2026-01-04T08:30:00', 'Utc')
       AppID = 'Windows Defender'; Url = 'https://go.microsoft.com/fwlink/?LinkId=52661'; ResultCode = 2; HResult = 0; Operation = 1 },
    @{ UpdateID = '33333333-3333-3333-3333-333333333333'; Rev = 1; Title = 'Update for Windows (KB5000001)'
       Description = 'd'; Date = [datetime]::SpecifyKind([datetime]'2026-01-01T00:00:00', 'Utc')
       AppID = 'UpdateOrchestrator'; Url = 'u'; ResultCode = 2; HResult = 0; Operation = 1 },
    @{ UpdateID = '55555555-5555-5555-5555-555555555555'; Rev = 3; Title = 'Contoso driver'
       Description = 'driver'; Date = [datetime]::SpecifyKind([datetime]'2026-01-03T00:00:00', 'Utc')
       AppID = 'UpdateOrchestrator'; Url = ''; ResultCode = 3; HResult = -2145124330; Operation = 1 },
    @{ UpdateID = '66666666-6666-6666-6666-666666666666'; Rev = 1; Title = 'Failed update (KB5999999)'
       Description = 'f'; Date = [datetime]::SpecifyKind([datetime]'2026-01-02T00:00:00', 'Utc')
       AppID = 'UpdateOrchestrator'; Url = ''; ResultCode = 4; HResult = -2145124329; Operation = 1 }
  )
}
'@
$r = Invoke-Case $scanFake $scanScript
CheckScanShape 'scan/kb + update id' $r
$j = $r.Json
CheckEq 'scan/kb + update id reboot_required' $true $j.reboot_required
CheckEq 'scan/kb + update id error_code' '' $j.error_code
CheckEq 'scan/kb + update id missing count' 2 $j.missing.Count
$m0 = $j.missing[0]; $m1 = $j.missing[1]
CheckEq 'scan/missing[0] kb_id' 'KB5034441' $m0.kb_id
CheckEq 'scan/missing[0] update_id' '11111111-1111-1111-1111-111111111111' $m0.update_id
CheckEq 'scan/missing[0] classification' 'Security Updates' $m0.classification
CheckEq 'scan/missing[0] product' 'Windows 11' $m0.product
CheckEq 'scan/missing[0] severity' 'Critical' $m0.severity
CheckEq 'scan/missing[0] reboot_required' $true $m0.reboot_required
CheckEq 'scan/missing[0] is_downloaded' $true $m0.is_downloaded
CheckEq 'scan/missing[0] support_url' 'https://support.microsoft.com/kb/5034441' $m0.support_url
# Dates are checked on the raw line: ConvertFrom-Json turns ISO strings into
# DateTime, which would hide the exact format Go and the server receive.
CheckRaw 'scan/missing[0] last_deployment_change' $r '"last_deployment_change":"2026-01-09T00:00:00.0000000Z"'
CheckEq 'scan/missing[1] kb_id is null' $null $m1.kb_id
CheckEq 'scan/missing[1] update_id' '22222222-2222-2222-2222-222222222222' $m1.update_id
CheckEq 'scan/missing[1] reboot_required' $false $m1.reboot_required
CheckEq 'scan/missing[1] support_url is null' $null $m1.support_url
CheckEq 'scan/missing[1] last_deployment_change is null' $null $m1.last_deployment_change
CheckEq 'scan/installed update ids (dedupe, removal and failure excluded)' `
    @('44444444-4444-4444-4444-444444444444', '55555555-5555-5555-5555-555555555555') `
    @($j.installed | ForEach-Object { $_.update_id })
$i0 = $j.installed[0]; $i1 = $j.installed[1]
CheckEq 'scan/installed[0] kb_id from title, upper-cased' 'KB2267602' $i0.kb_id
CheckEq 'scan/installed[0] revision_number' 200 $i0.revision_number
CheckRaw 'scan/installed[0] installed_on' $r '"installed_on":"2026-01-04T08:30:00.0000000Z"'
CheckEq 'scan/installed[0] client_application_id' 'Windows Defender' $i0.client_application_id
CheckEq 'scan/installed[0] result_code' 2 $i0.result_code
CheckEq 'scan/installed[0] hresult' '0x00000000' $i0.hresult
CheckEq 'scan/installed[1] kb_id is null without a KB in the title' $null $i1.kb_id
CheckEq 'scan/installed[1] succeeded-with-errors kept' 3 $i1.result_code
CheckEq 'scan/installed[1] negative hresult formatted unsigned' '0x80240016' $i1.hresult

# Exactly one missing update: PowerShell must not unroll it into a bare object.
$r = Invoke-Case @'
$Fake = @{ SystemReboot = $false; History = @()
  Updates = @( @{ Title = 'Only one'; KB = '5000002'; UpdateID = '77777777-7777-7777-7777-777777777777'; Reboot = 0; Downloaded = $false } ) }
'@ $scanScript
CheckScanShape 'scan/single update' $r
CheckEq 'scan/single update kb_id' 'KB5000002' $r.Json.missing[0].kb_id

# The search fails but history still answers: error_code set, installed kept.
$r = Invoke-Case @'
$Fake = @{ SystemReboot = $false; SearchHResult = -2145107924; Updates = @()
  History = @( @{ UpdateID = '88888888-8888-8888-8888-888888888888'; Rev = 1; Title = 'KB5000003'; Description = ''
                  Date = $null; AppID = 'x'; Url = ''; ResultCode = 2; HResult = 0; Operation = 1 } ) }
'@ $scanScript
CheckScanShape 'scan/search failure' $r
CheckEq 'scan/search failure missing' 0 $r.Json.missing.Count
CheckEq 'scan/search failure installed count' 1 $r.Json.installed.Count
CheckEq 'scan/search failure history_error_code' '' $r.Json.history_error_code
Check 'scan/search failure error_code is an 0x HRESULT' ($r.Json.error_code -match '^0x[0-9A-F]{8}$') "got: $($r.Json.error_code)"

# Windows Update is unreachable: both phases fail, reboot state unknown.
$r = Invoke-Case '$Fake = @{ SystemReboot = $null; SessionHResult = -2147023838; Updates = @(); History = @() }' $scanScript
CheckScanShape 'scan/service unavailable' $r
CheckEq 'scan/service unavailable reboot_required is null' $null $r.Json.reboot_required
CheckEq 'scan/service unavailable error_code' '0x80070422' $r.Json.error_code
CheckEq 'scan/service unavailable history_error_code' '0x80070422' $r.Json.history_error_code

# --- install ------------------------------------------------------------------

$installFake = @'
$Fake = @{
  SystemReboot = $false
  InstallReboot = $false
  History = @()
  Updates = @(
    @{ Title = 'Cumulative (KB5034441)'; KB = '5034441'; UpdateID = '11111111-1111-1111-1111-111111111111'; Reboot = 1; Downloaded = $true },
    @{ Title = 'Driver'; KB = $null; UpdateID = '22222222-2222-2222-2222-222222222222'; Reboot = 0; Downloaded = $false },
    @{ Title = 'Office (KB5002500)'; KB = '5002500'; UpdateID = '99999999-9999-9999-9999-999999999999'; Reboot = 0; Downloaded = $false },
    @{ Title = 'Not requested (KB5000009)'; KB = '5000009'; UpdateID = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; Reboot = 0; Downloaded = $false }
  )
  Install = @{
    '11111111-1111-1111-1111-111111111111' = @{ ResultCode = 2; HResult = 0; Reboot = $true }
    '22222222-2222-2222-2222-222222222222' = @{ ResultCode = 2; HResult = 0; Reboot = $false }
    '99999999-9999-9999-9999-999999999999' = @{ ResultCode = 4; HResult = -2145124329; Reboot = $false }
  }
}
'@

# Nothing missing.
$r = Invoke-Case '$Fake = @{ SystemReboot = $false; Updates = @(); History = @() }' `
    ((Get-InstallPrefix $true @() @()) + "`n" + $installScript)
CheckInstallShape 'install/no updates' $r
CheckEq 'install/no updates status' 'success' $r.Json.status
CheckEq 'install/no updates installed_kbs' 0 $r.Json.installed_kbs.Count
CheckEq 'install/no updates message' 'No missing updates found to install.' $r.Json.message

# Targets that match nothing applicable.
$r = Invoke-Case $installFake ((Get-InstallPrefix $false @('KB1234567') @()) + "`n" + $installScript)
CheckInstallShape 'install/no match' $r
CheckEq 'install/no match status' 'failed' $r.Json.status
Check 'install/no match message' ($r.Json.message -like 'None of the requested*') "got: $($r.Json.message)"

# KB + Update ID mix with a per-update failure: one by KB (reboot), one KB-less
# by Update ID, one by bare KB number that fails. The unrequested one is left.
$r = Invoke-Case $installFake ((Get-InstallPrefix $false @('KB5034441', '5002500') @('22222222-2222-2222-2222-222222222222')) + "`n" + $installScript)
CheckInstallShape 'install/kb + update id' $r
$j = $r.Json
CheckEq 'install/kb + update id status' 'partial' $j.status
CheckEq 'install/kb + update id installed_kbs' @('KB5034441', '22222222-2222-2222-2222-222222222222') @($j.installed_kbs)
CheckEq 'install/kb + update id failed_kbs' @('KB5002500') @($j.failed_kbs)
CheckEq 'install/kb + update id reboot_required from per-update result' $true $j.reboot_required
CheckEq 'install/kb + update id result identifiers' `
    @('KB5034441', '22222222-2222-2222-2222-222222222222', 'KB5002500') @($j.results | ForEach-Object { $_.identifier })
CheckEq 'install/kb + update id result codes' @(2, 2, 4) @($j.results | ForEach-Object { $_.result_code })
CheckEq 'install/kb + update id failure hresult' '0x80240017' $j.results[2].hresult
CheckEq 'install/kb + update id per-update reboot' @($true, $false, $false) @($j.results | ForEach-Object { $_.reboot_required })
CheckEq 'install/kb + update id message' 'Installed 2 update(s), 1 failed.' $j.message

# Exactly one target that installs and needs a reboot only per the aggregate.
$single = $installFake.Replace('InstallReboot = $false', 'InstallReboot = $true')
$r = Invoke-Case $single ((Get-InstallPrefix $false @() @('22222222-2222-2222-2222-222222222222')) + "`n" + $installScript)
CheckInstallShape 'install/single' $r
CheckEq 'install/single status' 'success' $r.Json.status
CheckEq 'install/single installed_kbs' @('22222222-2222-2222-2222-222222222222') @($r.Json.installed_kbs)
CheckEq 'install/single failed_kbs' 0 $r.Json.failed_kbs.Count
CheckEq 'install/single reboot_required from installation result' $true $r.Json.reboot_required

# Everything requested fails.
$allFail = $installFake.Replace("'11111111-1111-1111-1111-111111111111' = @{ ResultCode = 2", "'11111111-1111-1111-1111-111111111111' = @{ ResultCode = 5")
$r = Invoke-Case $allFail ((Get-InstallPrefix $false @('KB5034441', 'KB5002500') @()) + "`n" + $installScript)
CheckInstallShape 'install/all failed' $r
CheckEq 'install/all failed status' 'failed' $r.Json.status
CheckEq 'install/all failed installed_kbs' 0 $r.Json.installed_kbs.Count
CheckEq 'install/all failed failed_kbs' @('KB5034441', 'KB5002500') @($r.Json.failed_kbs)

# InstallAll takes every applicable update, the system-level reboot flag included.
$all = $installFake.Replace('SystemReboot = $false', 'SystemReboot = $true')
$r = Invoke-Case $all ((Get-InstallPrefix $true @() @()) + "`n" + $installScript)
CheckInstallShape 'install/all' $r
CheckEq 'install/all result count' 4 $r.Json.results.Count
CheckEq 'install/all status' 'partial' $r.Json.status

# Windows Update is unreachable.
$r = Invoke-Case '$Fake = @{ SystemReboot = $false; SessionHResult = -2147023838; Updates = @(); History = @() }' `
    ((Get-InstallPrefix $false @('KB5034441') @()) + "`n" + $installScript)
CheckInstallShape 'install/service unavailable' $r
CheckEq 'install/service unavailable status' 'failed' $r.Json.status
CheckEq 'install/service unavailable message' 'session unavailable' $r.Json.message

if ($failures -gt 0) { Write-Host "`n$failures assertion(s) failed"; exit 1 }
Write-Host "`nWUA scan and install scripts: all assertions passed"
