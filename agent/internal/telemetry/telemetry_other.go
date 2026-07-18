//go:build !linux && !windows

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import "os"

func osVersion() string { return "" }

func collect() Sample {
	return Sample{LoggedInUser: os.Getenv("USER")}
}
