// SPDX-License-Identifier: AGPL-3.0-only
// Package telemetry collects host metrics for heartbeats. Implementations are
// split by OS with build tags; this file holds the shared types and helpers.
package telemetry

import (
	"os"
	"runtime"
)

// Sample is one heartbeat's worth of host metrics.
type Sample struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemPercent    float64 `json:"mem_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	UptimeSeconds int64   `json:"uptime_seconds"`
	LoggedInUser  string  `json:"logged_in_user,omitempty"`
}

// HostInfo is collected once at enrollment.
type HostInfo struct {
	Hostname  string
	OS        string
	OSVersion string
}

// BasicHostInfo returns hostname and OS without platform-specific calls; the
// OSVersion is filled in per-platform where available.
func BasicHostInfo() HostInfo {
	host, _ := os.Hostname()
	return HostInfo{
		Hostname:  host,
		OS:        runtime.GOOS,
		OSVersion: osVersion(),
	}
}

// Collect returns a metrics sample. Platform files provide the real numbers;
// the fallback returns zeros so the agent still checks in on unsupported OSes.
func Collect() Sample {
	return collect()
}
