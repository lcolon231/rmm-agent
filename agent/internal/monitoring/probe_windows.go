//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// powerShell is a package var so Windows tests can drive the probe methods
// with captured output instead of a live system.
var powerShell pwsh.Runner = pwsh.Exec

func (platformProbe) DiskPercent(ctx context.Context, mount string) (float64, bool, string) {
	return diskPercent(ctx, powerShell, mount)
}

func (platformProbe) ServiceState(ctx context.Context, name string) (string, bool, string) {
	return serviceState(ctx, powerShell, name)
}

func (platformProbe) RebootPending(ctx context.Context) (RebootStatus, bool, string) {
	return rebootPending(ctx, powerShell)
}
