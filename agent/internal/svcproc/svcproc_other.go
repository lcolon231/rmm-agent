//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"fmt"
)

func platformListServices(_ context.Context) ([]ServiceInfo, error) {
	return nil, fmt.Errorf("service management is unsupported on this platform")
}

func platformControlService(_ context.Context, _ string, _ string) (string, error) {
	return "", fmt.Errorf("service control is unsupported on this platform")
}

func platformListProcesses(_ context.Context) ([]ProcessInfo, error) {
	return nil, fmt.Errorf("process management is unsupported on this platform")
}

func platformTerminateProcess(_ context.Context, _ int) error {
	return fmt.Errorf("process termination is unsupported on this platform")
}

func platformProcessName(_ context.Context, _ int) (string, error) {
	return "", fmt.Errorf("process lookup is unsupported on this platform")
}
