//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"testing"
	"time"
)

// The platform functions must route through the runPS seam; the glue itself is
// covered by the untagged svcproc_ps_test.go on every OS.
func TestWindowsPlatformFunctionsUseRunPSSeam(t *testing.T) {
	orig := runPS
	t.Cleanup(func() { runPS = orig })
	var calls []psCall
	reply := ""
	runPS = func(_ context.Context, timeout time.Duration, arg, script string) ([]byte, error) {
		calls = append(calls, psCall{timeout: timeout, arg: arg, script: script})
		return []byte(reply), nil
	}
	ctx := context.Background()

	reply = `{"Name":"Spooler","State":"Running"}`
	if s, err := platformListServices(ctx); err != nil || len(s) != 1 || s[0].Name != "Spooler" {
		t.Fatalf("platformListServices = (%+v, %v)", s, err)
	}
	reply = `{"ProcessId":4,"Name":"System"}`
	if p, err := platformListProcesses(ctx); err != nil || len(p) != 1 || p[0].PID != 4 {
		t.Fatalf("platformListProcesses = (%+v, %v)", p, err)
	}
	reply = "Stopped"
	if state, err := platformControlService(ctx, "Spooler", ActionStop); err != nil || state != "Stopped" {
		t.Fatalf("platformControlService = (%q, %v)", state, err)
	}
	reply = "notepad"
	if name, err := platformProcessName(ctx, 7); err != nil || name != "notepad.exe" {
		t.Fatalf("platformProcessName = (%q, %v)", name, err)
	}
	reply = ""
	if err := platformTerminateProcess(ctx, 7); err != nil {
		t.Fatalf("platformTerminateProcess = %v", err)
	}
	if len(calls) != 5 || calls[2].arg != "Spooler" || calls[4].arg != "7" {
		t.Fatalf("unexpected runner calls: %+v", calls)
	}
}
