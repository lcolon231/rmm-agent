//go:build !linux && !windows

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"os"
)

func osVersion() string { return "" }

func collect(_ context.Context) Sample {
	return Sample{LoggedInUser: os.Getenv("USER")}
}
