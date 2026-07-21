//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"os/exec"
)

func buildCommand(ctx context.Context, kind, script string) *exec.Cmd {
	switch kind {
	case KindShell, KindInventory:
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	case KindPowerShell:
		// PowerShell Core may exist on Unix as 'pwsh'; fall back to sh if not.
		if _, err := exec.LookPath("pwsh"); err == nil {
			return exec.CommandContext(ctx, "pwsh", "-NoProfile", "-Command", script)
		}
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	default:
		return nil
	}
}
