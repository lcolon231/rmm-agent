//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package power

import (
	"context"
	"fmt"
)

func platformSchedule(_ context.Context, _ string, _ int, _ string) (string, string, error) {
	return "unsupported", "Power operations are supported only on Windows", fmt.Errorf("power operations are unsupported on this platform")
}

func platformCancel(_ context.Context) (string, string, error) {
	return "unsupported", "Power cancellation is supported only on Windows", fmt.Errorf("power cancellation is unsupported on this platform")
}

func platformActiveUser(_ context.Context) (string, error) {
	return "", fmt.Errorf("active-user detection is unsupported on this platform")
}
