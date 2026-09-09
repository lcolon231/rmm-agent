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

func (platformProbe) RebootPending(ctx context.Context) (RebootStatus, bool, string) {
	// Report each source separately rather than ORing them: only the
	// WindowsUpdate key means an installed update is waiting on a restart.
	//
	// PendingFileRenameOperations is counted in place and its paths are never
	// emitted -- they routinely contain user names, and result detail is meant
	// to stay safe to forward to alert email and third-party webhooks. The
	// count is best-effort: it emits -1 on any failure so that a count error
	// cannot flip a working check to unknown.
	script := `$cbs = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'; ` +
		`$wu = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'; ` +
		`$item = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue; ` +
		`$pfr = $null -ne $item; $count = -1; ` +
		`if ($pfr) { try { $entries = @($item.PendingFileRenameOperations); $count = 0; ` +
		`for ($i = 0; $i -lt $entries.Count; $i += 2) { if (-not [string]::IsNullOrEmpty($entries[$i])) { $count++ } } } catch { $count = -1 } }; ` +
		`@($cbs.ToString().ToLowerInvariant(), $wu.ToString().ToLowerInvariant(), $pfr.ToString().ToLowerInvariant(), $count.ToString()) -join ([string][char]10)`
	out, err := powerShell(ctx, script)
	if err != nil {
		return RebootStatus{}, false, "reboot_probe_failed"
	}
	status, ok := parseRebootProbeOutput(out)
	if !ok {
		return RebootStatus{}, false, "reboot_probe_invalid"
	}
	return status, true, "sample_collected"
}
