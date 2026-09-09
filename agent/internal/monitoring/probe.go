// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"strconv"
	"strings"
)

// RebootSources reports which Windows reboot-required signals are set.
// Distinguishing them is the whole point: only WindowsUpdate means an
// installed update is waiting on a restart.
type RebootSources struct {
	ComponentBasedServicing bool
	WindowsUpdate           bool
	PendingFileRename       bool
	// PendingFileRenameCount counts the queued rename operations. The paths
	// themselves are never collected: they routinely carry user names and
	// installer temp paths, and a check result detail fans out over alert
	// email and third-party webhooks. The count is best-effort and never
	// decides status.
	PendingFileRenameCount int
}

// Pending reports whether any source requires a restart. Status logic depends
// on this alone, exactly as it did on the previous single boolean.
func (s RebootSources) Pending() bool {
	return s.ComponentBasedServicing || s.WindowsUpdate || s.PendingFileRename
}

type Probe interface {
	DiskPercent(context.Context, string) (float64, bool, string)
	ServiceState(context.Context, string) (string, bool, string)
	RebootPending(context.Context) (RebootSources, bool, string)
}

type platformProbe struct{}

func DefaultProbe() Probe { return platformProbe{} }

// parseRebootSources reads the four space-separated fields the probe script
// emits. The count is best-effort: an unparseable count leaves it at 0 rather
// than invalidating a sample whose source flags are perfectly usable.
func parseRebootSources(out string) (RebootSources, bool) {
	fields := strings.Fields(out)
	if len(fields) != 4 {
		return RebootSources{}, false
	}
	sources := RebootSources{}
	for index, target := range []*bool{
		&sources.ComponentBasedServicing,
		&sources.WindowsUpdate,
		&sources.PendingFileRename,
	} {
		value, err := strconv.ParseBool(fields[index])
		if err != nil {
			return RebootSources{}, false
		}
		*target = value
	}
	if count, err := strconv.Atoi(fields[3]); err == nil && count > 0 {
		sources.PendingFileRenameCount = count
	}
	return sources, true
}
