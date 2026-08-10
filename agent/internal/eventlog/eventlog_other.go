//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package eventlog

import (
	"context"
	"fmt"
)

func platformQuery(_ context.Context, _, _ string, _ int) ([]Record, error) {
	return nil, fmt.Errorf("event log queries are supported only on Windows")
}
