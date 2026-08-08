// SPDX-License-Identifier: AGPL-3.0-only

// Package patching runs the on-demand Windows Update scan (issue #51). The scan
// is triggered by the typed scan_updates command, not the heartbeat inventory
// path, because a live Windows Update search takes far longer than the
// per-section heartbeat budget. Its normalized result is reported through the
// existing windows_updates inventory section.
package patching

import (
	"time"

	"github.com/lcolon231/rmm/agent/internal/inventory"
)

// SectionWindowsUpdates is the inventory section name the scan result is
// reported under. It mirrors the server's InventorySection.windows_updates and
// is deliberately absent from inventory.AllSections: the section is populated on
// demand, never on the heartbeat cycle.
const SectionWindowsUpdates = "windows_updates"

// Caps mirror the server's bounds (MAX_MISSING_UPDATES, MAX_INSTALLED_UPDATES).
// The agent trims to these and reports StatusPartial; the server rejects more.
const (
	MaxMissingUpdates   = 512
	MaxInstalledUpdates = 1024
)

// The exact fields each row may carry — the server model is extra="forbid", so
// the payload must contain only these keys. Any other field the collector
// produced is dropped rather than risking a rejected submission.
var missingFields = []string{
	"title", "kb_id", "update_id", "classification", "product",
	"severity", "reboot_required", "is_downloaded", "support_url",
	"last_deployment_change",
}

var installedFields = []string{
	"kb_id", "title", "description", "installed_on", "installed_by",
	"client_application_id", "support_url",
}

// Summary is the bounded, non-sensitive result reported back as the
// scan_updates command output so an operator sees an immediate outcome. The full
// normalized data travels in the windows_updates inventory section.
type Summary struct {
	Status         string `json:"status"`
	ScannedAt      string `json:"scanned_at,omitempty"`
	MissingCount   int    `json:"missing_count"`
	InstalledCount int    `json:"installed_count"`
	RebootRequired *bool  `json:"reboot_required,omitempty"`
	ErrorCode      string `json:"error_code,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
}

// allowlist copies only the permitted keys whose values are non-nil, so the
// server's extra="forbid" model accepts the row.
func allowlist(row map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields))
	for _, key := range fields {
		if v, ok := row[key]; ok && v != nil {
			out[key] = v
		}
	}
	return out
}

func nonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// BuildSection normalizes raw, already-flattened scan rows into the bounded
// windows_updates section and its summary. It is pure and platform-independent
// so it can be exercised with captured fixtures; the platform collector is only
// responsible for producing the flat rows.
//
// A missing-update row without a usable title is dropped: a titleless update is
// noise, and the server model requires the title. Over-cap rows are trimmed and
// the section is reported StatusPartial. A non-empty errorCode marks the section
// StatusUnavailable regardless of counts.
func BuildSection(
	missing, installed []map[string]any,
	scannedAt time.Time,
	rebootRequired *bool,
	errorCode string,
) (inventory.Section, Summary) {
	normMissing := make([]map[string]any, 0, len(missing))
	for _, row := range missing {
		if !nonEmptyString(row["title"]) {
			continue
		}
		normMissing = append(normMissing, allowlist(row, missingFields))
	}
	normInstalled := make([]map[string]any, 0, len(installed))
	for _, row := range installed {
		normInstalled = append(normInstalled, allowlist(row, installedFields))
	}

	truncated := false
	if len(normMissing) > MaxMissingUpdates {
		normMissing = normMissing[:MaxMissingUpdates]
		truncated = true
	}
	if len(normInstalled) > MaxInstalledUpdates {
		normInstalled = normInstalled[:MaxInstalledUpdates]
		truncated = true
	}

	scannedISO := scannedAt.UTC().Format(time.RFC3339)
	payload := map[string]any{
		"scanned_at": scannedISO,
		"source":     "windows_update_agent",
		"missing":    normMissing,
		"installed":  normInstalled,
	}
	if rebootRequired != nil {
		payload["reboot_required"] = *rebootRequired
	}
	if errorCode != "" {
		payload["error_code"] = errorCode
	}

	status := inventory.StatusOK
	switch {
	case errorCode != "":
		status = inventory.StatusUnavailable
	case truncated:
		status = inventory.StatusPartial
	}

	section := inventory.Section{
		Section:     SectionWindowsUpdates,
		Status:      status,
		CollectedAt: scannedAt.UTC(),
		Payload:     payload,
	}
	summary := Summary{
		Status:         status,
		ScannedAt:      scannedISO,
		MissingCount:   len(normMissing),
		InstalledCount: len(normInstalled),
		RebootRequired: rebootRequired,
		ErrorCode:      errorCode,
		Truncated:      truncated,
	}
	return section, summary
}

// UnsupportedSection is the result on a platform that cannot scan Windows
// Updates. The section carries StatusUnsupported so the server records "this
// endpoint cannot report updates" rather than "no updates are missing".
func UnsupportedSection() (inventory.Section, Summary) {
	now := time.Now().UTC()
	section := inventory.Section{
		Section:     SectionWindowsUpdates,
		Status:      inventory.StatusUnsupported,
		CollectedAt: now,
		Payload: map[string]any{
			"missing":   []map[string]any{},
			"installed": []map[string]any{},
		},
	}
	return section, Summary{Status: inventory.StatusUnsupported}
}
