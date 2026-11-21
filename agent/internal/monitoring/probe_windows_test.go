//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

func withPowerShell(t *testing.T, run pwsh.Runner) {
	t.Helper()
	orig := powerShell
	powerShell = run
	t.Cleanup(func() { powerShell = orig })
}

// The platform methods must route through the powerShell seam; the logic
// itself is covered by the untagged probe_ps_test.go on every OS.
func TestWindowsProbeMethodsUsePowerShellSeam(t *testing.T) {
	fake := &pwshtest.Fake{Reply: func(s pwsh.Script) (pwsh.Result, error) {
		switch {
		case strings.Contains(s.Body, "Win32_LogicalDisk"):
			return pwsh.Result{Stdout: []byte("12,5")}, nil
		case strings.Contains(s.Body, "Get-Service"):
			return pwsh.Result{Stdout: []byte("Running")}, nil
		default:
			return pwsh.Result{Stdout: []byte("false\ntrue\nfalse\n-1")}, nil
		}
	}}
	withPowerShell(t, fake.Run)
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
	if calls := fake.Calls(); len(calls) != 3 || calls[0].Env["NL_MOUNT"] != "C:'" {
		t.Fatalf("unexpected calls: %+v", calls)
	}
}
