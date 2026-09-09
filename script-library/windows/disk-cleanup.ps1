# SPDX-License-Identifier: AGPL-3.0-only
# Library parameters are injected before this script; do not use a param() block.
$ErrorActionPreference = 'Stop'
$preview = $true
$ageDays = 7
if (Test-Path variable:NL_PARAM_Preview) { $preview = $NL_PARAM_Preview }
if (Test-Path variable:NL_PARAM_MinimumAgeDays) { $ageDays = $NL_PARAM_MinimumAgeDays }
if ($preview -isnot [bool]) { throw 'Preview must be a boolean.' }
if ($ageDays -isnot [ValueType] -or $ageDays -is [bool] -or $ageDays -lt 1 -or $ageDays -gt 365 -or $ageDays % 1 -ne 0) {
    throw 'MinimumAgeDays must be a whole number from 1 to 365.'
}
if (-not $env:windir) { throw 'Windows directory is unavailable.' }
$root = [IO.Path]::GetFullPath((Join-Path $env:windir 'Temp'))
# Reject redirected roots and ancestors before inspecting or deleting anything.
$ancestor = Get-Item -LiteralPath $root -Force
if (-not $ancestor.PSIsContainer) { throw 'Windows Temp is not a directory.' }
while ($null -ne $ancestor) {
    if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Cleanup path contains a reparse point.' }
    $ancestor = $ancestor.Parent
}
$cutoff = [datetime]::UtcNow.AddDays(-$ageDays)
$report = [ordered]@{ Preview = $preview; Root = $root; MinimumAgeDays = $ageDays; CandidateFiles = 0; CandidateBytes = 0L; DeletedFiles = 0; DeletedBytes = 0L; FailedFiles = 0 }
# Deliberately nonrecursive: never traverse junctions or remove temp subdirectories.
foreach ($file in Get-ChildItem -LiteralPath $root -File -Force) {
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.LastWriteTimeUtc -ge $cutoff) { continue }
    $report.CandidateFiles++
    $report.CandidateBytes += $file.Length
    if ($preview) { continue }
    try {
        $current = Get-Item -LiteralPath $file.FullName -Force
        if ($current.PSIsContainer -or $current.Attributes -band [IO.FileAttributes]::ReparsePoint -or $current.LastWriteTimeUtc -ge $cutoff) { continue }
        if (-not [string]::Equals($current.DirectoryName, $root, [StringComparison]::OrdinalIgnoreCase)) { throw 'File is outside the cleanup root.' }
        Remove-Item -LiteralPath $current.FullName -Force -ErrorAction Stop
        $report.DeletedFiles++
        $report.DeletedBytes += $current.Length
    } catch { $report.FailedFiles++ }
}
$report | ConvertTo-Json -Compress
if ($report.FailedFiles -gt 0) { throw 'Some eligible files could not be removed; see FailedFiles.' }
