//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"fmt"
	"time"
)

func platformVerifyAuthenticode(_ context.Context, _ string) (bool, string, error) {
	return false, "", fmt.Errorf("authenticode verification is unsupported on this platform")
}

func platformRunInstaller(_ context.Context, _ string, _ string, _ []string, _ time.Duration) (int, error) {
	return -1, fmt.Errorf("software deployment is unsupported on this platform")
}

func platformReadProductCode(_ context.Context, _ string) string {
	return ""
}
