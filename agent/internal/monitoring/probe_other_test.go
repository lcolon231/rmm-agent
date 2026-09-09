//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"testing"
)

func TestNonWindowsRebootProbeReportsUnsupported(t *testing.T) {
	sources, ok, reason := DefaultProbe().RebootPending(context.Background())
	if ok || reason != "unsupported_platform" || sources != (RebootSources{}) {
		t.Fatalf("RebootPending = %#v, %v, %q", sources, ok, reason)
	}
}
