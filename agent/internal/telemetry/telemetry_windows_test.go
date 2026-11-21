//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

// fakePS routes every PowerShell run to fn and fails the test if any run is
// unbounded, since telemetry runs on the heartbeat path.
func fakePS(t *testing.T, fn func(script string) (string, error)) {
	t.Helper()
	orig := runPS
	fake := &pwshtest.Fake{Reply: func(s pwsh.Script) (pwsh.Result, error) {
		if s.Timeout != psTimeout {
			t.Errorf("script %q ran with timeout %s, want %s", s.Body, s.Timeout, psTimeout)
		}
		out, err := fn(s.Body)
		return pwsh.Result{Stdout: []byte(out)}, err
	}}
	runPS = fake.Run
	t.Cleanup(func() { runPS = orig })
}

func TestCollectWindowsAvailable(t *testing.T) {
	fakePS(t, func(script string) (string, error) {
		switch {
		case strings.Contains(script, "LoadPercentage"):
			return "12,5\r\n", nil
		case strings.Contains(script, "TotalVisibleMemorySize"):
			return "50.25", nil
		case strings.Contains(script, "Win32_LogicalDisk"):
			return "70", nil
		case strings.Contains(script, "LastBootUpTime"):
			return "3600", nil
		case strings.Contains(script, "UserName"):
			return " HOST\\alice \r\n", nil
		}
		return "", errors.New("unexpected")
	})
	s := Collect()
	if s.CPUPercent != 12.5 || s.MemPercent != 50.25 || s.DiskPercent != 70 || s.UptimeSeconds != 3600 {
		t.Fatalf("unexpected sample: %+v", s)
	}
	if !s.CPUAvailable || !s.MemAvailable || !s.DiskAvailable || !s.UptimeAvailable {
		t.Fatalf("expected all available: %+v", s)
	}
	if s.LoggedInUser != "HOST\\alice" {
		t.Fatalf("user = %q", s.LoggedInUser)
	}
}

func TestCollectWindowsErrorsMarkUnavailable(t *testing.T) {
	fakePS(t, func(string) (string, error) { return "", errors.New("boom") })
	t.Setenv("USERNAME", "fallback")
	s := CollectContext(context.Background())
	if s.CPUAvailable || s.MemAvailable || s.DiskAvailable || s.UptimeAvailable {
		t.Fatalf("expected none available: %+v", s)
	}
	if s.CPUPercent != 0 || s.UptimeSeconds != 0 {
		t.Fatalf("expected zero values: %+v", s)
	}
	if s.LoggedInUser != "fallback" {
		t.Fatalf("user = %q", s.LoggedInUser)
	}
}

func TestCollectWindowsGarbageMarksUnavailable(t *testing.T) {
	fakePS(t, func(string) (string, error) { return "not-a-number", nil })
	s := Collect()
	if s.CPUAvailable || s.MemAvailable || s.DiskAvailable || s.UptimeAvailable {
		t.Fatalf("expected none available: %+v", s)
	}
}

func TestOSVersionWindows(t *testing.T) {
	fakePS(t, func(string) (string, error) { return " 10.0.22631\r\n", nil })
	if got := osVersion(); got != "10.0.22631" {
		t.Fatalf("got %q", got)
	}
	fakePS(t, func(string) (string, error) { return "", errors.New("x") })
	if got := osVersion(); got != "" {
		t.Fatalf("got %q", got)
	}
}
