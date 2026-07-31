// SPDX-License-Identifier: AGPL-3.0-only

// Package inventory collects a bounded hardware snapshot and reports it per
// section, so a failure collecting one class of hardware cannot void the rest.
//
// The agent advertises a per-section content hash on every heartbeat and only
// uploads the sections the server asks for. That keeps the beat small, avoids
// resending unchanged hardware forever, and gives the server the change signal
// it needs without parsing payloads it already holds.
package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// SchemaVersion must match the server's INVENTORY_SCHEMA_VERSION. The server
// rejects anything else, so a mismatched agent fails loudly at upload rather
// than silently storing a shape the server cannot interpret.
const SchemaVersion = 1

// Section names. These are the wire values; the server validates against the
// same set and rejects unknown ones.
const (
	SectionSystem  = "system"
	SectionCPU     = "cpu"
	SectionMemory  = "memory"
	SectionStorage = "storage"
	SectionNetwork = "network"
)

// AllSections is collection order, which is also the order sections appear in
// an upload. Stable ordering keeps request bodies comparable between runs.
var AllSections = []string{
	SectionSystem,
	SectionCPU,
	SectionMemory,
	SectionStorage,
	SectionNetwork,
}

// Status explains why a section looks the way it does. These mirror the
// server's InventorySectionStatus exactly.
const (
	// StatusOK means collected completely.
	StatusOK = "ok"
	// StatusPartial means collected, but bounded away — some rows are missing
	// because the machine reported more than the caps below allow.
	StatusPartial = "partial"
	// StatusUnavailable means the platform supports this but collection failed.
	StatusUnavailable = "unavailable"
	// StatusUnsupported means the platform cannot report it at all.
	StatusUnsupported = "unsupported"
)

// Caps mirror the server's bounds. The agent trims to these and reports
// StatusPartial; the server rejects anything over, so trimming here is what
// keeps an unusual machine reporting *something* instead of nothing.
const (
	MaxMemoryModules       = 64
	MaxDisks               = 64
	MaxVolumes             = 128
	MaxNetworkAdapters     = 64
	MaxAddressesPerAdapter = 32
)

// Section is one collected section ready for upload.
type Section struct {
	Section     string         `json:"section"`
	Status      string         `json:"status"`
	CollectedAt time.Time      `json:"collected_at"`
	Payload     map[string]any `json:"payload"`
}

// Submission is the upload body for POST /agents/me/inventory.
type Submission struct {
	InventorySchemaVersion int       `json:"inventory_schema_version"`
	AgentVersion           string    `json:"agent_version,omitempty"`
	Sections               []Section `json:"sections"`
}

// ContentHash returns the SHA-256 over the section's canonical payload.
//
// Go's encoding/json sorts map keys and emits no incidental whitespace, which
// matches the server's json.dumps(sort_keys=True, separators=(",", ":")). Both
// sides therefore compute the same digest over the same bytes — that identity
// is what makes the heartbeat hash comparison meaningful rather than advisory.
func ContentHash(payload map[string]any) (string, error) {
	if payload == nil {
		payload = map[string]any{}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Hashes maps section name to content hash for the heartbeat advertisement.
// A section that cannot be hashed is omitted rather than sent with a wrong or
// empty digest, since the server treats a differing hash as "resend this".
func Hashes(sections []Section) map[string]string {
	out := make(map[string]string, len(sections))
	for _, section := range sections {
		hash, err := ContentHash(section.Payload)
		if err != nil {
			continue
		}
		out[section.Section] = hash
	}
	return out
}

// Select returns the subset of sections named in want, preserving collection
// order. Names the agent did not collect are ignored: the server can only ask
// for what was advertised, so an unknown name means the two sides disagree and
// the agent's view is the authoritative one about what it can produce.
func Select(sections []Section, want []string) []Section {
	if len(want) == 0 {
		return nil
	}
	wanted := make(map[string]struct{}, len(want))
	for _, name := range want {
		wanted[name] = struct{}{}
	}
	out := make([]Section, 0, len(want))
	for _, section := range sections {
		if _, ok := wanted[section.Section]; ok {
			out = append(out, section)
		}
	}
	return out
}

// Collect gathers every supported section. It never returns an error: a
// section that cannot be collected is returned with a non-ok status, because
// "we could not read the BIOS" is itself inventory a technician needs.
func Collect(ctx context.Context) []Section {
	return collect(ctx)
}

// unsupportedSections is the fallback for platforms with no collector. Windows
// is the primary support target; other platforms report explicitly rather than
// returning empty payloads that would read as "this machine has no disks".
func unsupportedSections(now time.Time) []Section {
	out := make([]Section, 0, len(AllSections))
	for _, name := range AllSections {
		out = append(out, Section{
			Section:     name,
			Status:      StatusUnsupported,
			CollectedAt: now,
			Payload:     map[string]any{},
		})
	}
	return out
}
