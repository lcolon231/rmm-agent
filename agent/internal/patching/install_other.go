//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"fmt"
)

// Install is unsupported off Windows: there is no Windows Update service available.
func Install(_ context.Context, _ InstallTargets) (InstallResult, error) {
	return InstallResult{
		Status:  "unsupported",
		Message: "windows update installation is only supported on Windows operating systems",
	}, fmt.Errorf("windows update installation is unsupported on this platform")
}
