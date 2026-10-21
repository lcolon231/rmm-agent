//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package power

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

type recordedCall struct {
	name string
	args []string
}

func fakeCommand(t *testing.T, out []byte, err error) *[]recordedCall {
	t.Helper()
	orig := commandContext
	var calls []recordedCall
	commandContext = func(_ context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, recordedCall{name, append([]string(nil), args...)})
		return out, err
	}
	t.Cleanup(func() { commandContext = orig })
	return &calls
}

func TestPlatformScheduleArgv(t *testing.T) {
	tests := []struct {
		name   string
		kind   string
		delay  int
		reason string
		want   []string
	}{
		{"reboot", KindReboot, 60, "Patch window", []string{"/r", "/t", "60", "/d", "p:4:1", "/c", "Patch window"}},
		{"shutdown", KindShutdown, 300, "Decommission", []string{"/s", "/t", "300", "/d", "p:4:1", "/c", "Decommission"}},
		{"zero delay", KindReboot, 0, "now", []string{"/r", "/t", "0", "/d", "p:4:1", "/c", "now"}},
		{"reason with spaces and quotes stays one arg", KindShutdown, 10, `say "hi" now`, []string{"/s", "/t", "10", "/d", "p:4:1", "/c", `say "hi" now`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := fakeCommand(t, nil, nil)
			status, detail, err := platformSchedule(context.Background(), tt.kind, tt.delay, tt.reason)
			if err != nil || status != "scheduled" || detail == "" {
				t.Fatalf("got %q %q %v", status, detail, err)
			}
			if len(*calls) != 1 || (*calls)[0].name != "shutdown.exe" || !reflect.DeepEqual((*calls)[0].args, tt.want) {
				t.Fatalf("calls = %#v", *calls)
			}
		})
	}
}

func TestPlatformScheduleFailure(t *testing.T) {
	fakeCommand(t, []byte("  Access is denied.\r\n"), errors.New("exit status 5"))
	status, detail, err := platformSchedule(context.Background(), KindReboot, 5, "r")
	if status != "failed" || detail == "" || err == nil {
		t.Fatalf("got %q %q %v", status, detail, err)
	}
	if !strings.Contains(err.Error(), "exit status 5") || !strings.HasSuffix(err.Error(), "Access is denied.") {
		t.Fatalf("err = %v", err)
	}
}

func TestPlatformCancel(t *testing.T) {
	t.Run("argv and success", func(t *testing.T) {
		calls := fakeCommand(t, nil, nil)
		status, _, err := platformCancel(context.Background())
		if err != nil || status != "cancelled" {
			t.Fatalf("got %q %v", status, err)
		}
		if len(*calls) != 1 || (*calls)[0].name != "shutdown.exe" || !reflect.DeepEqual((*calls)[0].args, []string{"/a"}) {
			t.Fatalf("calls = %#v", *calls)
		}
	})
	t.Run("non exit error fails", func(t *testing.T) {
		fakeCommand(t, []byte("boom\n"), errors.New("start failed"))
		status, _, err := platformCancel(context.Background())
		if status != "failed" || err == nil || !strings.HasSuffix(err.Error(), "boom") {
			t.Fatalf("got %q %v", status, err)
		}
	})
	t.Run("exit code 1116 means none pending", func(t *testing.T) {
		// Run a real cmd.exe that exits 1116 to obtain a genuine *exec.ExitError.
		exitErr := exec.Command("cmd.exe", "/c", "exit 1116").Run()
		if _, ok := exitErr.(*exec.ExitError); !ok {
			t.Skipf("could not produce ExitError: %v", exitErr)
		}
		fakeCommand(t, nil, exitErr)
		status, _, err := platformCancel(context.Background())
		if err != nil || status != "none_pending" {
			t.Fatalf("got %q %v", status, err)
		}
	})
	t.Run("other exit code fails", func(t *testing.T) {
		exitErr := exec.Command("cmd.exe", "/c", "exit 2").Run()
		if _, ok := exitErr.(*exec.ExitError); !ok {
			t.Skipf("could not produce ExitError: %v", exitErr)
		}
		fakeCommand(t, nil, exitErr)
		status, _, err := platformCancel(context.Background())
		if err == nil || status != "failed" {
			t.Fatalf("got %q %v", status, err)
		}
	})
}

func TestPlatformActiveUser(t *testing.T) {
	calls := fakeCommand(t, []byte(" HOST\alice\r\n"), nil)
	user, err := platformActiveUser(context.Background())
	if err != nil || user != "HOST\alice" {
		t.Fatalf("got %q %v", user, err)
	}
	want := []string{"-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystem).UserName"}
	if len(*calls) != 1 || (*calls)[0].name != "powershell.exe" || !reflect.DeepEqual((*calls)[0].args, want) {
		t.Fatalf("calls = %#v", *calls)
	}

	fakeCommand(t, nil, errors.New("nope"))
	if user, err := platformActiveUser(context.Background()); err == nil || user != "" {
		t.Fatalf("got %q %v", user, err)
	}
}
