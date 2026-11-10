//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// powerShell is a package var so Windows tests can drive the probe methods
// with captured output instead of a live system.
var powerShell psRunner = execPowerShell

func execPowerShell(ctx context.Context, script string) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(probeCtx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script).Output()
	return strings.TrimSpace(string(out)), err
}

func (platformProbe) DiskPercent(ctx context.Context, mount string) (float64, bool, string) {
	return diskPercent(ctx, powerShell, mount)
}

func (platformProbe) ServiceState(ctx context.Context, name string) (string, bool, string) {
	return serviceState(ctx, powerShell, name)
}

func (platformProbe) RebootPending(ctx context.Context) (RebootStatus, bool, string) {
	return rebootPending(ctx, powerShell)
}
