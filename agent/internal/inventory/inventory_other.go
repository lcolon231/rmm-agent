//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"time"
)

// collect reports every section as unsupported off Windows. Linux and macOS
// builds exist for development only (#70/#71 cover real support), and an
// honest "unsupported" is better evidence than a plausible-looking empty
// payload.
func collect(_ context.Context) []Section {
	return unsupportedSections(time.Now().UTC())
}
