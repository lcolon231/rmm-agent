# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
function Assert($Condition, $Message) { if (-not $Condition) { throw $Message } }
$scripts = $PSScriptRoot
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('nodelink-library-test-' + [guid]::NewGuid())
$originalWindows = $env:windir
try {
    $temp = New-Item -ItemType Directory -Path (Join-Path $fixture 'Temp') -Force
    $old = Join-Path $temp.FullName 'old.tmp'
    $recent = Join-Path $temp.FullName 'recent.tmp'
    Set-Content -LiteralPath $old -Value 'old'
    Set-Content -LiteralPath $recent -Value 'recent'
    (Get-Item -LiteralPath $old).LastWriteTimeUtc = [datetime]::UtcNow.AddDays(-30)
    $nested = New-Item -ItemType Directory -Path (Join-Path $temp.FullName 'nested')
    Set-Content -LiteralPath (Join-Path $nested.FullName 'keep.tmp') -Value 'keep'
    $env:windir = $fixture
    $preview = & (Join-Path $scripts 'disk-cleanup.ps1') | ConvertFrom-Json
    Assert ($preview.Preview -and $preview.CandidateFiles -eq 1) 'Default must preview old files only'
    Assert (Test-Path -LiteralPath $old) 'Preview deleted a file'
    $result = & { $NL_PARAM_Preview = $false; & (Join-Path $scripts 'disk-cleanup.ps1') } | ConvertFrom-Json
    Assert ($result.DeletedFiles -eq 1) 'Cleanup did not delete the eligible file'
    Assert (-not (Test-Path -LiteralPath $old)) 'Old file remains'
    Assert (Test-Path -LiteralPath $recent) 'Recent file was removed'
    Assert (Test-Path -LiteralPath (Join-Path $nested.FullName 'keep.tmp')) 'Nested file was removed'
    $rejected = $false
    try { & { $NL_PARAM_MinimumAgeDays = -1; & (Join-Path $scripts 'disk-cleanup.ps1') } } catch { $rejected = $true }
    Assert $rejected 'Negative cleanup age accepted'

    $actions = [System.Collections.Generic.List[string]]::new()
    $serviceState = @{ Status = 'Running' }
    function Get-Service { param($Name) [pscustomobject]@{ Name = $Name; DisplayName = 'Test service'; Status = $serviceState.Status; StartType = 'Automatic' } }
    function Start-Service { param($InputObject) $actions.Add('start'); $serviceState.Status = 'Running' }
    function Stop-Service { param($InputObject) $actions.Add('stop'); $serviceState.Status = 'Stopped' }
    function Restart-Service { param($InputObject) $actions.Add('restart') }
    $status = & { $NL_PARAM_ServiceName = 'Example'; & (Join-Path $scripts 'service-management.ps1') } | ConvertFrom-Json
    Assert ($status.Action -eq 'status' -and $actions.Count -eq 0) 'Status changed a service'
    $result = & { $NL_PARAM_ServiceName = 'Example'; $NL_PARAM_Action = 'restart'; & (Join-Path $scripts 'service-management.ps1') } | ConvertFrom-Json
    Assert ($actions.Count -eq 1 -and $actions[0] -eq 'restart') 'Wrong service action'
    $result = & { $NL_PARAM_ServiceName = 'Example'; $NL_PARAM_Action = 'stop'; & (Join-Path $scripts 'service-management.ps1') } | ConvertFrom-Json
    Assert ($result.Status -eq 'Stopped' -and $actions[1] -eq 'stop') 'Stop failed'
    $result = & { $NL_PARAM_ServiceName = 'Example'; $NL_PARAM_Action = 'start'; & (Join-Path $scripts 'service-management.ps1') } | ConvertFrom-Json
    Assert ($result.Status -eq 'Running' -and $actions[2] -eq 'start') 'Start failed'
    $rejected = $false
    try { & { $NL_PARAM_ServiceName = '*'; & (Join-Path $scripts 'service-management.ps1') } } catch { $rejected = $true }
    Assert $rejected 'Wildcard service name accepted'
    function Get-CimInstance { throw 'Mock CIM unavailable' }
    function Get-MpComputerStatus { throw 'Mock Defender unavailable' }
    $health = & (Join-Path $scripts 'health-check.ps1') | ConvertFrom-Json
    Assert ($health.Sections.OperatingSystem.Status -eq 'unavailable') 'CIM failure hidden'
    Assert ($health.Sections.Defender.Status -eq 'unavailable') 'Defender failure hidden'
    Assert ($health.Sections.RebootIndicators.Status -eq 'ok') 'One failure prevented other sections'
    Write-Output 'PASS: cleanup preview, age filter, deletion scope, invalid age, all service actions, wildcard rejection, partial health collection'
} finally {
    $env:windir = $originalWindows
    # Only remove the unique test directory created above, after checking its parent and name.
    $resolved = [IO.Path]::GetFullPath($fixture)
    Assert ([IO.Path]::GetDirectoryName($resolved).TrimEnd('\') -eq [IO.Path]::GetTempPath().TrimEnd('\')) 'Unexpected test parent'
    Assert ([IO.Path]::GetFileName($resolved) -like 'nodelink-library-test-*') 'Unexpected test directory'
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
