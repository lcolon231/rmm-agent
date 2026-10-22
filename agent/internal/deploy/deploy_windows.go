//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"time"

	"github.com/lcolon231/rmm/agent/internal/authenticode"
)

// Process seams, swapped by tests so no installer or PowerShell ever starts.
var (
	runProcess    processRunner       = execProcess
	runPowerShell authenticode.Runner = authenticode.Exec
)

func platformRunInstaller(ctx context.Context, installerType, path string, args []string, timeout time.Duration) (int, error) {
	return runInstallerWith(ctx, runProcess, installerType, path, args, timeout)
}

// platformVerifyAuthenticode returns whether the file carries a Valid
// Authenticode signature and the signer certificate's SHA-1 thumbprint.
func platformVerifyAuthenticode(ctx context.Context, path string) (bool, string, error) {
	return authenticode.Verify(ctx, runPowerShell, pathEnvVar, path)
}

func platformReadProductCode(ctx context.Context, path string) string {
	return readProductCodeWith(ctx, runPowerShell, path)
}
