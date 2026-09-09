# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$action = 'status'
if (Test-Path variable:NL_PARAM_Action) { $action = $NL_PARAM_Action }
if (@('status', 'start', 'stop', 'restart') -cnotcontains $action) { throw 'Action must be status, start, stop, or restart.' }
if (-not (Test-Path variable:NL_PARAM_ServiceName) -or $NL_PARAM_ServiceName -isnot [string] -or
    [string]::IsNullOrWhiteSpace($NL_PARAM_ServiceName) -or $NL_PARAM_ServiceName.Length -gt 256 -or
    $NL_PARAM_ServiceName.IndexOfAny([char[]]'*?[]') -ge 0) {
    throw 'ServiceName must be one exact service name without wildcards.'
}
$service = Get-Service -Name $NL_PARAM_ServiceName -ErrorAction Stop
if (@($service).Count -ne 1 -or $service.Name -ine $NL_PARAM_ServiceName) { throw 'Expected one exact service match.' }
$before = [string]$service.Status
# No Force: do not implicitly stop dependent services.
switch ($action) {
    'start' { Start-Service -InputObject $service -ErrorAction Stop }
    'stop' { Stop-Service -InputObject $service -ErrorAction Stop }
    'restart' { Restart-Service -InputObject $service -ErrorAction Stop }
}
$after = Get-Service -Name $NL_PARAM_ServiceName -ErrorAction Stop
[ordered]@{
    ServiceName = $after.Name
    DisplayName = $after.DisplayName
    Action = $action
    PreviousStatus = $before
    Status = [string]$after.Status
    StartType = [string]$after.StartType
} | ConvertTo-Json -Compress
if (($action -in @('start', 'restart') -and [string]$after.Status -ne 'Running') -or
    ($action -eq 'stop' -and [string]$after.Status -ne 'Stopped')) {
    throw 'Service has not reached the requested state; check its status again.'
}
