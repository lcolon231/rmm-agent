//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import "context"

func (platformProbe) DiskPercent(context.Context, string) (float64, bool, string) {
	return 0, false, "unsupported_platform"
}

func (platformProbe) ServiceState(context.Context, string) (string, bool, string) {
	return "", false, "unsupported_platform"
}

func (platformProbe) RebootPending(context.Context) (RebootSources, bool, string) {
	return RebootSources{}, false, "unsupported_platform"
}
