//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

// openLikeTheLoader opens path the way the Windows image loader holds a running
// executable: read access, sharing reads and *deletes*. FILE_SHARE_DELETE is the
// detail that makes the swap possible — a rename needs DELETE access to the
// target, so an image held without it cannot be displaced, while one held the
// loader's way can. os.Open would model the former, not the latter.
func openLikeTheLoader(t *testing.T, path string) syscall.Handle {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("open %s with loader sharing mode: %v", path, err)
	}
	return handle
}

func writeBinary(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestReplaceRunningBinaryDisplacesLoaderHeldImage covers the Windows-specific
// half of the atomic swap: the image of a running process cannot be overwritten,
// but it can be renamed out of the way, and the new binary then takes the
// vacated path. This is the case that makes self-update possible at all.
func TestReplaceRunningBinaryDisplacesLoaderHeldImage(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	src := filepath.Join(dir, "staged.exe")
	writeBinary(t, dest, oldBinary)
	writeBinary(t, src, newBinary)

	handle := openLikeTheLoader(t, dest)
	// Closed exactly once, below, once the displaced image may be pruned. A
	// second CloseHandle on a released handle could hit a recycled one.
	closeOnce := func() {
		if handle != syscall.InvalidHandle {
			syscall.CloseHandle(handle)
			handle = syscall.InvalidHandle
		}
	}
	defer closeOnce()

	if err := replaceRunningBinary(src, dest); err != nil {
		t.Fatalf("replaceRunningBinary: %v", err)
	}
	installed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != newBinary {
		t.Fatalf("installed content = %q, want the new build", installed)
	}

	// The displaced image survives while the old process still holds it, so it
	// is pruned on a later start rather than at swap time.
	matches, err := filepath.Glob(dest + ".old-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected the previous image to be displaced, found %v", matches)
	}
	closeOnce()
	pruneDisplacedImages(dest)
	if matches, _ := filepath.Glob(dest + ".old-*"); len(matches) != 0 {
		t.Fatalf("displaced images were not pruned: %v", matches)
	}
}

// TestReplaceRunningBinaryLeavesDestinationWhenDisplaceIsRefused covers the
// other side: when something holds the binary without allowing deletes, the
// rename is refused. The swap must then fail cleanly with the original still in
// place — an endpoint must never be left without an executable.
func TestReplaceRunningBinaryLeavesDestinationWhenDisplaceIsRefused(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	src := filepath.Join(dir, "staged.exe")
	writeBinary(t, dest, oldBinary)
	writeBinary(t, src, newBinary)

	// os.Open shares reads and writes but not deletes, so the rename is denied.
	held, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := replaceRunningBinary(src, dest); err == nil {
		t.Fatal("a destination that cannot be displaced must fail the swap")
	}
	surviving, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination must still exist after a refused swap: %v", err)
	}
	if string(surviving) != oldBinary {
		t.Fatalf("destination content = %q, want the original build", surviving)
	}
}

// TestReplaceRunningBinaryRestoresOnFailure asserts the destination is never
// left missing when the second rename fails after the original was displaced.
func TestReplaceRunningBinaryRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	writeBinary(t, dest, oldBinary)
	missing := filepath.Join(dir, "does-not-exist.exe")

	if err := replaceRunningBinary(missing, dest); err == nil {
		t.Fatal("replacing from a missing source must fail")
	}
	restored, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination must still exist after a failed replace: %v", err)
	}
	if string(restored) != oldBinary {
		t.Fatalf("destination content = %q, want the original build", restored)
	}
	if matches, _ := filepath.Glob(dest + ".old-*"); len(matches) != 0 {
		t.Fatalf("a failed replace must not leave a displaced image: %v", matches)
	}
}

type startCall struct {
	name string
	args []string
}

// fakeRestart swaps the service-restart seams so no helper process starts.
func fakeRestart(t *testing.T, lookErr, startErr error) *[]startCall {
	t.Helper()
	origLook, origStart := lookPath, startDetached
	var calls []startCall
	lookPath = func(file string) (string, error) {
		if lookErr != nil {
			return "", lookErr
		}
		return `C:\Windows\System32\` + file, nil
	}
	startDetached = func(name string, args ...string) error {
		calls = append(calls, startCall{name, append([]string(nil), args...)})
		return startErr
	}
	t.Cleanup(func() { lookPath, startDetached = origLook, origStart })
	return &calls
}

func TestPlatformRestartService(t *testing.T) {
	name, args := restartCommand()
	tests := []struct {
		name      string
		lookErr   error
		startErr  error
		wantErr   string
		wantStart []startCall
	}{
		{"starts the fixed helper", nil, nil, "", []startCall{{name, args}}},
		{"cmd.exe missing starts nothing", errors.New("not found"), nil, "cmd.exe is unavailable", nil},
		{"start failure is reported", nil, errors.New("access denied"), "request service restart: access denied", []startCall{{name, args}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := fakeRestart(t, tt.lookErr, tt.startErr)
			err := platformRestartService(context.Background())
			if (err == nil) != (tt.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if !reflect.DeepEqual(*calls, tt.wantStart) {
				t.Fatalf("started %#v, want %#v", *calls, tt.wantStart)
			}
		})
	}
}

func TestPlatformVerifyAuthenticode(t *testing.T) {
	tests := []struct {
		name      string
		out       string
		err       error
		wantValid bool
		wantThumb string
		wantErr   bool
	}{
		{"valid", "Valid|AABBCCDDEEFF00112233445566778899AABBCCDD\r\n", nil, true, "AABBCCDDEEFF00112233445566778899AABBCCDD", false},
		{"not signed", "NotSigned|\r\n", nil, false, "", false},
		{"powershell failed", "", errors.New("exit status 1"), false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := runPowerShell
			var env []string
			var ran string
			runPowerShell = func(_ context.Context, e []string, name string, _ ...string) ([]byte, error) {
				env, ran = e, name
				return []byte(tt.out), tt.err
			}
			t.Cleanup(func() { runPowerShell = orig })

			valid, thumb, err := platformVerifyAuthenticode(context.Background(), `C:\NodeLink\update\staged-1`)
			if valid != tt.wantValid || thumb != tt.wantThumb || (err != nil) != tt.wantErr {
				t.Fatalf("got %v, %q, %v", valid, thumb, err)
			}
			if ran != "powershell.exe" || !reflect.DeepEqual(env, []string{`NL_UPDATE_PATH=C:\NodeLink\update\staged-1`}) {
				t.Fatalf("ran %q with env %#v", ran, env)
			}
		})
	}
}
