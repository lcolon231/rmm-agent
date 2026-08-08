//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"

	"github.com/lcolon231/rmm/agent/internal/inventory"
)

// Scan is unsupported off Windows: there is no Windows Update service to query.
// It returns an unsupported section (not an error) so the command still reports
// a clean, bounded outcome rather than a failure.
func Scan(_ context.Context) (inventory.Section, Summary, error) {
	section, summary := UnsupportedSection()
	return section, summary, nil
}
