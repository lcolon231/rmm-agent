//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"context"
	"fmt"
	"os"
)

func platformVerifyAuthenticode(_ context.Context, _ string) (bool, string, error) {
	return false, "", fmt.Errorf("authenticode verification is unsupported on this platform")
}

// platformRestartService fails closed off Windows. Managed self-update is a
// Windows-service capability (see docs/WINDOWS-SUPPORT-MATRIX.md); the agent
// does not advertise agent-self-update-v1 on other platforms, so reaching this
// means the endpoint was asked to do something it never offered.
func platformRestartService(_ context.Context) error {
	return fmt.Errorf("managed service restart is unsupported on this platform")
}

// replaceRunningBinary is a plain rename off Windows: replacing the file a
// running process was loaded from is permitted, and rename within one directory
// is atomic.
func replaceRunningBinary(src, dest string) error {
	return os.Rename(src, dest)
}

func pruneDisplacedImages(_ string) {}
