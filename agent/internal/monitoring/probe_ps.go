// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// probeTimeout bounds each probe's PowerShell run.
const probeTimeout = 5 * time.Second

// The probe logic below runs through a pwsh.Runner and lives in an untagged
// file so every CI job covers it, not only the Windows one. The Windows build
// binds the runner to pwsh.Exec; tests feed captured output.

// probe runs body with env as its arguments and returns the trimmed stdout.
func probe(ctx context.Context, run pwsh.Runner, body string, env map[string]string) (string, error) {
	res, err := run(ctx, pwsh.Script{Body: body, Env: env, Timeout: probeTimeout})
	return strings.TrimSpace(string(res.Stdout)), err
}

// diskPercentScript reads the policy-supplied mount point from NL_MOUNT.
// Filtering an already-created object avoids putting it into a WQL
// expression, which has a quoting language of its own.
const diskPercentScript = `$d=Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -eq $env:NL_MOUNT } | Select-Object -First 1; if ($null -eq $d -or $d.Size -le 0) { 'missing' } else { [math]::Round((($d.Size-$d.FreeSpace)/$d.Size)*100,2) }`

func diskPercent(ctx context.Context, run pwsh.Runner, mount string) (float64, bool, string) {
	out, err := probe(ctx, run, diskPercentScript, map[string]string{"NL_MOUNT": mount})
	if err != nil {
		return 0, false, "disk_probe_failed"
	}
	if out == "missing" {
		return 0, false, "disk_not_found"
	}
	// [math]::Round output follows the endpoint's culture, so a German locale
	// prints a decimal comma.
	value, err := strconv.ParseFloat(strings.ReplaceAll(out, ",", "."), 64)
	if err != nil {
		return 0, false, "disk_probe_invalid"
	}
	return value, true, "sample_collected"
}

// serviceStateScript reads the policy-supplied service name from NL_SERVICE.
const serviceStateScript = `$s=Get-Service -Name $env:NL_SERVICE -ErrorAction SilentlyContinue; if ($null -eq $s) { 'absent' } else { $s.Status.ToString().ToLowerInvariant() }`

func serviceState(ctx context.Context, run pwsh.Runner, name string) (string, bool, string) {
	out, err := probe(ctx, run, serviceStateScript, map[string]string{"NL_SERVICE": name})
	if err != nil {
		return "", false, "service_probe_failed"
	}
	if out == "" {
		return "", false, "service_probe_invalid"
	}
	return strings.ToLower(out), true, "sample_collected"
}

// rebootPending runs the reboot-source probe. agent/test/reboot_probe_script.ps1
// extracts the script literal below (from "func rebootPending" up to the
// probe call) and executes it against stubbed registry state, so keep the
// script as backtick chunks inside this function.
func rebootPending(ctx context.Context, run pwsh.Runner) (RebootStatus, bool, string) {
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
		// The count stays -1 until the whole walk succeeds. A property getter
		// that fails yields $null rather than raising, so an unreadable value
		// must be tested for directly -- catch alone would let a failed query
		// report zero, which reads as "no renames queued" rather than
		// "unknown".
		`if ($pfr) { $entries = $null; try { $entries = $item.PendingFileRenameOperations } catch { $entries = $null }; ` +
		`if ($null -ne $entries) { $list = @($entries); $n = 0; ` +
		`for ($i = 0; $i -lt $list.Count; $i += 2) { if (-not [string]::IsNullOrEmpty($list[$i])) { $n++ } }; $count = $n } }; ` +
		`@($cbs.ToString().ToLowerInvariant(), $wu.ToString().ToLowerInvariant(), $pfr.ToString().ToLowerInvariant(), $count.ToString()) -join ([string][char]10)`
	out, err := probe(ctx, run, script, nil)
	if err != nil {
		return RebootStatus{}, false, "reboot_probe_failed"
	}
	status, ok := parseRebootProbeOutput(out)
	if !ok {
		return RebootStatus{}, false, "reboot_probe_invalid"
	}
	return status, true, "sample_collected"
}
