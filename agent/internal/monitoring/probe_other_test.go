//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"testing"
)

func TestDefaultProbeIsUnsupportedOffWindows(t *testing.T) {
	probe := DefaultProbe()
	ctx := context.Background()
	if _, ok, cause := probe.DiskPercent(ctx, "/"); ok || cause != "unsupported_platform" {
		t.Fatalf("DiskPercent = (%v, %q), want unsupported", ok, cause)
	}
	if _, ok, cause := probe.ServiceState(ctx, "sshd"); ok || cause != "unsupported_platform" {
		t.Fatalf("ServiceState = (%v, %q), want unsupported", ok, cause)
	}
	if _, ok, cause := probe.RebootPending(ctx); ok || cause != "unsupported_platform" {
		t.Fatalf("RebootPending = (%v, %q), want unsupported", ok, cause)
	}
}
