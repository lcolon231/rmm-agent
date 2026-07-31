// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Sanity bound on rows. The byte budget below is the constraint that actually
// binds: at the server's 255-character field limits one entry approaches 1 KiB,
// so ~250 worst-case entries already exceed MaxSectionBytes. Trimming to this
// count alone would let the agent build a payload the server rejects on every
// attempt, and the machines with the most software would silently never report
// any — so FitSoftwareEntries trims to bytes, and this is only a ceiling.
const MaxSoftwareEntries = 1024

// MaxSectionBytes mirrors the server's MAX_INVENTORY_SECTION_BYTES. The server
// rejects rather than truncates, so the agent must land under this itself.
const MaxSectionBytes = 256 * 1024

// Registration architecture. This describes the registry view an entry came
// from, not the binary: a 64-bit installer can register a 32-bit program.
const (
	ArchX86     = "x86"
	ArchX64     = "x64"
	ArchARM64   = "arm64"
	ArchUnknown = "unknown"
)

const (
	ScopeMachine = "machine"
	ScopeUser    = "user"
)

// RawSoftware is one uninstall-registry row as read from the endpoint, before
// normalization. Keeping the raw shape separate from the wire shape lets the
// hard part — normalization, dedup, and bounding — be tested on any platform.
type RawSoftware struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
	Identifier  string `json:"identifier"`
	// Source view: "machine_x64", "machine_x86", or "user".
	Source string `json:"source"`
}

// sourceRank orders the registry views for deduplication. A program registered
// in more than one view is reported once, from the most authoritative: the
// native machine view beats the 32-bit compatibility view, and both beat a
// per-user registration.
func sourceRank(source string) int {
	switch source {
	case "machine_x64":
		return 3
	case "machine_x86":
		return 2
	case "user":
		return 1
	default:
		return 0
	}
}

func architectureFor(source string) string {
	switch source {
	case "machine_x64":
		return ArchX64
	case "machine_x86":
		return ArchX86
	default:
		// A per-user registration says nothing about architecture, and
		// guessing would put a false fact in inventory.
		return ArchUnknown
	}
}

func scopeFor(source string) string {
	if source == "user" {
		return ScopeUser
	}
	return ScopeMachine
}

// parseInstallDate accepts only the documented Windows form. The registry
// stores InstallDate inconsistently — absent, localized, or malformed — and a
// guessed date is worse than no date, so anything else is dropped.
func parseInstallDate(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if len(trimmed) != 8 {
		return "", false
	}
	parsed, err := time.Parse("20060102", trimmed)
	if err != nil {
		return "", false
	}
	return parsed.UTC().Format(time.RFC3339), true
}

// dedupKey identifies "the same program". Case- and space-insensitive on name
// so that "7-Zip 23.01" and "7-Zip  23.01 " collapse, but version-sensitive so
// two installed major versions stay two rows.
func dedupKey(name, version string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), " ")) +
		"\x00" + strings.ToLower(strings.TrimSpace(version))
}

// NormalizeSoftware turns raw registry rows into wire entries: it drops
// unnamed rows, dedupes across registry views, and sorts deterministically.
//
// Sorting matters beyond tidiness: the section's content hash is computed over
// this payload, and registry enumeration order is not stable between runs. An
// unsorted list would hash differently every collection and make an unchanged
// machine re-upload its software list forever.
func NormalizeSoftware(rows []RawSoftware) []map[string]any {
	best := make(map[string]RawSoftware, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(row.Name)
		if name == "" {
			// No display name means a registry artifact, not a program.
			continue
		}
		row.Name = name
		key := dedupKey(name, row.Version)
		if existing, ok := best[key]; ok && sourceRank(existing.Source) >= sourceRank(row.Source) {
			continue
		}
		best[key] = row
	}

	entries := make([]map[string]any, 0, len(best))
	for _, row := range best {
		entry := map[string]any{
			"name":         row.Name,
			"architecture": architectureFor(row.Source),
			"scope":        scopeFor(row.Source),
		}
		if version := strings.TrimSpace(row.Version); version != "" {
			entry["version"] = version
		}
		if publisher := strings.TrimSpace(row.Publisher); publisher != "" {
			entry["publisher"] = publisher
		}
		if identifier := strings.TrimSpace(row.Identifier); identifier != "" {
			entry["identifier"] = identifier
		}
		if installed, ok := parseInstallDate(row.InstallDate); ok {
			entry["install_date"] = installed
		}
		entries = append(entries, entry)
	}

	sort.Slice(entries, func(i, j int) bool {
		left, right := entries[i], entries[j]
		li, _ := left["name"].(string)
		ri, _ := right["name"].(string)
		if !strings.EqualFold(li, ri) {
			return strings.ToLower(li) < strings.ToLower(ri)
		}
		lv, _ := left["version"].(string)
		rv, _ := right["version"].(string)
		return lv < rv
	})
	return entries
}

// FitSoftwareEntries bounds the payload so the server will accept it, and
// reports whether anything was dropped.
//
// The count ceiling is applied first, then entries are dropped from the tail
// until the encoded payload fits MaxSectionBytes. Both are needed: the count
// bounds pathological row counts, and the byte fit is what prevents a machine
// with unusually long program names from being rejected on every attempt.
func FitSoftwareEntries(entries []map[string]any) (map[string]any, bool) {
	trimmed := false
	if len(entries) > MaxSoftwareEntries {
		entries = entries[:MaxSoftwareEntries]
		trimmed = true
	}

	payload := map[string]any{"entries": entries}
	for len(entries) > 0 {
		encoded, err := json.Marshal(payload)
		if err != nil {
			// Unencodable payload: report nothing rather than something wrong.
			return map[string]any{"entries": []map[string]any{}}, true
		}
		if len(encoded) <= MaxSectionBytes {
			return payload, trimmed
		}
		// Scale down proportionally to the overshoot rather than one row at a
		// time, so a badly oversized list converges in a few passes instead of
		// hundreds of re-encodes.
		keep := len(entries) * MaxSectionBytes / len(encoded)
		if keep >= len(entries) {
			keep = len(entries) - 1
		}
		if keep < 0 {
			keep = 0
		}
		entries = entries[:keep]
		payload = map[string]any{"entries": entries}
		trimmed = true
	}
	return payload, trimmed
}

// SoftwareSection assembles the collected rows into a section, choosing the
// status from whether the payload had to be bounded.
func SoftwareSection(rows []RawSoftware, collectedAt time.Time) Section {
	payload, trimmed := FitSoftwareEntries(NormalizeSoftware(rows))
	status := StatusOK
	if trimmed {
		status = StatusPartial
	}
	return Section{
		Section:     SectionInstalledSoftware,
		Status:      status,
		CollectedAt: collectedAt,
		Payload:     payload,
	}
}
