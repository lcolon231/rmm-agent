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

func (platformProbe) RebootPending(ctx context.Context) (bool, bool, string) {
	script := `$pending=(Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') -or (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') -or ($null -ne (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)); $pending.ToString().ToLowerInvariant()`
	out, err := powerShell(ctx, script)
	if err != nil {
		return false, false, "reboot_probe_failed"
	}
	value, err := strconv.ParseBool(out)
	if err != nil {
		return false, false, "reboot_probe_invalid"
	}
	return value, true, "sample_collected"
}
