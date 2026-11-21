//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// runPS is a package var so Windows tests can drive the platform functions
// with captured output instead of a live system.
var runPS pwsh.Runner = pwsh.Exec

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
