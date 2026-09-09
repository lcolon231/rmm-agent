// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
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
}

// Any reports whether a restart is pending from any source. Status logic has
// always turned on this value; splitting the sources apart does not move it.
func (s RebootSources) Any() bool {
	return s.ComponentBasedServicing || s.WindowsUpdate || s.PendingFileRename
}

// RebootStatus is one reboot probe reading.
//
// PendingFileRenameCount is best-effort. The presence test in Sources stays the
// authority for status, so a failed count query leaves CountKnown false rather
// than failing the probe and flipping a working check to unknown.
//
// The registry value behind the count lists file paths that routinely contain
// user names and installer temp directories. Result detail is the alert payload
// operators and integrations read, and is meant to stay safe to forward to
// alert email and third-party webhooks, so a path in it would leave the tenant
// boundary. No field on this type can carry one: the count is deliberately all
// the probe reports.
type RebootStatus struct {
	Sources                RebootSources
	PendingFileRenameCount int
	CountKnown             bool
}

// Detail renders the reading for CheckResult.detail. The keys match the payload
// the server parses; the count is omitted entirely when the best-effort query
// did not produce one, so an absent key is never read as zero.
func (s RebootStatus) Detail() map[string]any {
	detail := map[string]any{
		"sources": map[string]any{
			"component_based_servicing": s.Sources.ComponentBasedServicing,
			"windows_update":            s.Sources.WindowsUpdate,
			"pending_file_rename":       s.Sources.PendingFileRename,
		},
	}
	if s.CountKnown {
		detail["pending_file_rename_count"] = s.PendingFileRenameCount
	}
	return detail
}

// parseRebootProbeOutput reads the four lines the Windows probe script emits:
// the three source booleans, then the pending file-rename count. A negative or
// unparseable count means the best-effort query failed and is reported as
// unknown; only an unreadable source line fails the parse.
func parseRebootProbeOutput(out string) (RebootStatus, bool) {
	normalized := strings.ReplaceAll(out, "\r\n", "\n")
	lines := strings.Split(strings.TrimSpace(normalized), "\n")
	if len(lines) != 4 {
		return RebootStatus{}, false
	}
	flags := make([]bool, 3)
	for index := range flags {
		value, err := strconv.ParseBool(strings.TrimSpace(lines[index]))
		if err != nil {
			return RebootStatus{}, false
		}
		flags[index] = value
	}
	status := RebootStatus{Sources: RebootSources{
		ComponentBasedServicing: flags[0],
		WindowsUpdate:           flags[1],
		PendingFileRename:       flags[2],
	}}
	if count, err := strconv.Atoi(strings.TrimSpace(lines[3])); err == nil && count >= 0 {
		status.PendingFileRenameCount = count
		status.CountKnown = true
	}
	return status, true
}
