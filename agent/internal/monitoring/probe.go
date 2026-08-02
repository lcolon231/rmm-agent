// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import "context"

type Probe interface {
	DiskPercent(context.Context, string) (float64, bool, string)
	ServiceState(context.Context, string) (string, bool, string)
	RebootPending(context.Context) (bool, bool, string)
}

type platformProbe struct{}

func DefaultProbe() Probe { return platformProbe{} }
