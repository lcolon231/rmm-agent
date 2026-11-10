//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"strings"
	"testing"
)

func withPowerShell(t *testing.T, run psRunner) {
	t.Helper()
	orig := powerShell
	powerShell = run
	t.Cleanup(func() { powerShell = orig })
}

// The platform methods must route through the powerShell seam; the logic
// itself is covered by the untagged probe_ps_test.go on every OS.
func TestWindowsProbeMethodsUsePowerShellSeam(t *testing.T) {
	var scripts []string
	withPowerShell(t, func(_ context.Context, script string) (string, error) {
		scripts = append(scripts, script)
		switch {
		case strings.Contains(script, "Win32_LogicalDisk"):
			return "12,5", nil
		case strings.Contains(script, "Get-Service"):
			return "Running", nil
		default:
			return "false\ntrue\nfalse\n-1", nil
		}
	})
	probe := DefaultProbe()
	if v, ok, cause := probe.DiskPercent(context.Background(), "C:'"); !ok || v != 12.5 || cause != "sample_collected" {
		t.Fatalf("DiskPercent = (%v, %v, %q)", v, ok, cause)
	}
	if s, ok, _ := probe.ServiceState(context.Background(), "Spooler"); !ok || s != "running" {
		t.Fatalf("ServiceState = (%q, %v)", s, ok)
	}
	if r, ok, _ := probe.RebootPending(context.Background()); !ok || !r.Sources.WindowsUpdate || r.CountKnown {
		t.Fatalf("RebootPending = (%+v, %v)", r, ok)
	}
	if len(scripts) != 3 || !strings.Contains(scripts[0], "$mount='C:'''") {
		t.Fatalf("unexpected scripts: %q", scripts)
	}
}
