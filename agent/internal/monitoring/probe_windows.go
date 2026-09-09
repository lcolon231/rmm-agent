//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func powerShell(ctx context.Context, script string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	return strings.TrimSpace(string(out)), err
}

func psQuote(value string) string { return strings.ReplaceAll(value, "'", "''") }

func (platformProbe) DiskPercent(ctx context.Context, mount string) (float64, bool, string) {
	// Keep the policy-supplied mount point inside a single-quoted PowerShell
	// literal. Filtering an already-created object avoids interpolating it into
	// a WQL expression, which has a second quoting language of its own.
	script := fmt.Sprintf(`$mount='%s'; $d=Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -eq $mount } | Select-Object -First 1; if ($null -eq $d -or $d.Size -le 0) { 'missing' } else { [math]::Round((($d.Size-$d.FreeSpace)/$d.Size)*100,2) }`, psQuote(mount))
	out, err := powerShell(ctx, script)
	if err != nil {
		return 0, false, "disk_probe_failed"
	}
	if out == "missing" {
		return 0, false, "disk_not_found"
	}
	value, err := strconv.ParseFloat(strings.ReplaceAll(out, ",", "."), 64)
	if err != nil {
		return 0, false, "disk_probe_invalid"
	}
	return value, true, "sample_collected"
}

func (platformProbe) ServiceState(ctx context.Context, name string) (string, bool, string) {
	script := fmt.Sprintf(`$s=Get-Service -Name '%s' -ErrorAction SilentlyContinue; if ($null -eq $s) { 'absent' } else { $s.Status.ToString().ToLowerInvariant() }`, psQuote(name))
	out, err := powerShell(ctx, script)
	if err != nil {
		return "", false, "service_probe_failed"
	}
	if out == "" {
		return "", false, "service_probe_invalid"
	}
	return strings.ToLower(out), true, "sample_collected"
}

// rebootProbeScript reports the three reboot-required registry sources as
// independent flags plus a count of queued rename operations. It deliberately
// emits no registry values: only presence tests and a count leave the endpoint.
// PendingFileRenameOperations stores source/destination pairs, so the operation
// count is half the entry count. The count is wrapped so that a failure to read
// it degrades to 0 rather than failing the whole probe.
const rebootProbeScript = `$cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$entry = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
$pfr = $null -ne $entry
$count = 0
if ($pfr) { try { $count = [math]::Floor(@($entry.PendingFileRenameOperations).Count / 2) } catch { $count = 0 } }
'{0} {1} {2} {3}' -f $cbs.ToString().ToLowerInvariant(), $wu.ToString().ToLowerInvariant(), $pfr.ToString().ToLowerInvariant(), $count`

func (platformProbe) RebootPending(ctx context.Context) (RebootSources, bool, string) {
	out, err := powerShell(ctx, rebootProbeScript)
	if err != nil {
		return RebootSources{}, false, "reboot_probe_failed"
	}
	sources, ok := parseRebootSources(out)
	if !ok {
		return RebootSources{}, false, "reboot_probe_invalid"
	}
	return sources, true, "sample_collected"
}
