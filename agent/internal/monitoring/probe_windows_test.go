//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"testing"
)

func TestWindowsMonitoringProbeEscapesPowerShellLiterals(t *testing.T) {
	if got := psQuote("C:'; Remove-Item C:\\important; '"); got != "C:''; Remove-Item C:\\important; ''" {
		t.Fatalf("psQuote returned %q", got)
	}
	var _ Probe = DefaultProbe()
}
