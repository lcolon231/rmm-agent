//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func waitForPIDFile(t *testing.T, path string) uint32 {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			value, parseErr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32)
			if parseErr != nil {
				t.Fatalf("parse child PID %q: %v", data, parseErr)
			}
			return uint32(value)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("child PID file %s was not created", path)
	return 0
}

func assertProcessTerminated(t *testing.T, pid uint32) {
	t.Helper()
	process, err := windows.OpenProcess(
		windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION,
		false,
		pid,
	)
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return // the process object is already gone
		}
		t.Fatalf("open descendant %d to verify termination: %v", pid, err)
	}
	defer windows.CloseHandle(process)
	status, err := windows.WaitForSingleObject(process, 5_000)
	if err != nil {
		t.Fatalf("wait for descendant %d: %v", pid, err)
	}
	if status != windows.WAIT_OBJECT_0 {
		t.Fatalf("descendant process %d survived command termination", pid)
	}
}

func childScript(pidPath string, wait bool) string {
	escaped := strings.ReplaceAll(pidPath, "'", "''")
	script := fmt.Sprintf(
		"$child = Start-Process -FilePath 'powershell.exe' "+
			"-ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 60' "+
			"-PassThru; Set-Content -LiteralPath '%s' -Value $child.Id",
		escaped,
	)
	if wait {
		script += "; Wait-Process -Id $child.Id"
	}
	return script
}

func TestWindowsJobObjectKillsDescendantsOnCancellation(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "cancel-child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Result, 1)
	go func() {
		done <- RunContext(ctx, KindPowerShell, childScript(pidPath, true))
	}()

	pid := waitForPIDFile(t, pidPath)
	cancel()
	select {
	case result := <-done:
		if result.ExitCode != -1 || !strings.Contains(result.Stderr, "cancelled") {
			t.Fatalf("unexpected cancellation result: %+v", result)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancelled command did not return")
	}
	assertProcessTerminated(t, pid)
}

func TestWindowsJobObjectKillsDeferredDescendantsOnParentExit(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "deferred-child.pid")
	result := RunContext(
		context.Background(),
		KindPowerShell,
		childScript(pidPath, false),
	)
	if result.ExitCode != 0 {
		t.Fatalf("parent command failed: %+v", result)
	}
	pid := waitForPIDFile(t, pidPath)
	assertProcessTerminated(t, pid)
}
