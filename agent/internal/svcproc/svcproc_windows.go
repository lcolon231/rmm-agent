//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"os/exec"
	"time"
)

// runPS is a package var so Windows tests can drive the platform functions
// with captured output instead of a live system.
var runPS psRunner = execPS

func execPS(ctx context.Context, timeout time.Duration, arg, script string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(bounded, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if arg != "" {
		cmd.Env = append(cmd.Environ(), "NL_ARG="+arg)
	}
	return cmd.CombinedOutput()
}

func platformListServices(ctx context.Context) ([]ServiceInfo, error) {
	return psListServices(ctx, runPS)
}

func platformListProcesses(ctx context.Context) ([]ProcessInfo, error) {
	return psListProcesses(ctx, runPS)
}

func platformControlService(ctx context.Context, name, action string) (string, error) {
	return psControlService(ctx, runPS, name, action)
}

func platformProcessName(ctx context.Context, pid int) (string, error) {
	return psProcessName(ctx, runPS, pid)
}

func platformTerminateProcess(ctx context.Context, pid int) error {
	return psTerminateProcess(ctx, runPS, pid)
}
