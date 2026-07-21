//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"os/exec"
)

func buildCommand(ctx context.Context, kind, script string) *exec.Cmd {
	switch kind {
	case KindPowerShell, KindInventory:
		return exec.CommandContext(ctx, "powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-Command", script)
	case KindShell:
		return exec.CommandContext(ctx, "cmd.exe", "/C", script)
	default:
		return nil
	}
}
