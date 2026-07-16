//go:build !linux && !windows

package telemetry

import "os"

func osVersion() string { return "" }

func collect() Sample {
	return Sample{LoggedInUser: os.Getenv("USER")}
}
