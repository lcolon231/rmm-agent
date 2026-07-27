//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"os/exec"
	"syscall"
)

func buildCommand(kind, script string) *exec.Cmd {
	switch kind {
	case KindShell, KindInventory:
		return exec.Command("/bin/sh", "-c", script)
	case KindPowerShell:
		// PowerShell Core may exist on Unix as 'pwsh'; fall back to sh if not.
		if _, err := exec.LookPath("pwsh"); err == nil {
			return exec.Command("pwsh", "-NoProfile", "-Command", script)
		}
		return exec.Command("/bin/sh", "-c", script)
	default:
		return nil
	}
}

// runCommand puts every command in a fresh process group. Cancellation and
// normal parent exit kill descendants that remain in the command's group.
func runCommand(ctx context.Context, cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	pgid := cmd.Process.Pid
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		return err
	case <-ctx.Done():
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
		return ctx.Err()
	}
}
