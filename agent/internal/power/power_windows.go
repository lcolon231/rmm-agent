//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package power

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func commandContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return exec.CommandContext(bounded, name, args...).CombinedOutput()
}

func platformSchedule(ctx context.Context, kind string, delay int, reason string) (string, string, error) {
	mode := "/s"
	if kind == KindReboot {
		mode = "/r"
	}
	out, err := commandContext(ctx, "shutdown.exe", mode, "/t", strconv.Itoa(delay), "/d", "p:4:1", "/c", reason)
	if err != nil {
		return "failed", "Windows rejected the scheduled action", fmt.Errorf("schedule Windows power action: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return "scheduled", "Windows accepted the delayed power action", nil
}

func platformCancel(ctx context.Context) (string, string, error) {
	out, err := commandContext(ctx, "shutdown.exe", "/a")
	if err == nil {
		return "cancelled", "Windows cancelled the pending power action", nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1116 {
		return "none_pending", "No pending Windows power action existed", nil
	}
	return "failed", "Windows rejected the cancellation", fmt.Errorf("cancel Windows power action: %w: %s", err, strings.TrimSpace(string(out)))
}

func platformActiveUser(ctx context.Context) (string, error) {
	out, err := commandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_ComputerSystem).UserName")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
