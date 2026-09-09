# SPDX-License-Identifier: AGPL-3.0-only
$ErrorActionPreference = 'Stop'
$report = [ordered]@{ ComputerName = $env:COMPUTERNAME; CollectedAtUtc = [datetime]::UtcNow.ToString('o'); Sections = [ordered]@{} }
function Read-HealthSection($Name, [scriptblock]$Collect) {
    try { $report.Sections[$Name] = @{ Status = 'ok'; Data = (& $Collect) } }
    catch { $report.Sections[$Name] = @{ Status = 'unavailable'; Error = $_.Exception.Message } }
}
Read-HealthSection 'OperatingSystem' {
    $os = Get-CimInstance Win32_OperatingSystem -OperationTimeoutSec 10
    [ordered]@{ Name = $os.Caption; Version = $os.Version; LastBoot = $os.LastBootUpTime.ToUniversalTime().ToString('o'); UptimeHours = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1); FreeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024); TotalMemoryMB = [math]::Round($os.TotalVisibleMemorySize / 1024) }
}
Read-HealthSection 'Disks' {
    @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' -OperationTimeoutSec 10 | ForEach-Object {
        [ordered]@{ Drive = $_.DeviceID; SizeGB = [math]::Round($_.Size / 1GB, 2); FreeGB = [math]::Round($_.FreeSpace / 1GB, 2); FreePercent = $(if ($_.Size -gt 0) { [math]::Round(100 * $_.FreeSpace / $_.Size, 1) } else { $null }) }
    })
}
Read-HealthSection 'Defender' {
    Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated
}
Read-HealthSection 'RebootIndicators' {
    [ordered]@{
        ComponentServicing = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WindowsUpdate = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    }
}
Read-HealthSection 'StoppedAutomaticServices' {
    @(Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State='Stopped'" -OperationTimeoutSec 10 | Select-Object -First 50 Name, DisplayName, State)
}
$report | ConvertTo-Json -Depth 7 -Compress
