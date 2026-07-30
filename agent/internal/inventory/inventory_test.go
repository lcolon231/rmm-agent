// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"encoding/json"
	"testing"
	"time"
)

// The digests below are SHA-256 over the canonical encoding the server also
// produces (json.dumps(sort_keys=True, separators=(",", ":"))). They are
// pinned here so a change to Go's encoder — or to this package — cannot
// silently break hash agreement with the server. The Python side asserts the
// same values in server/tests/test_inventory.py.
func TestContentHashMatchesPinnedCrossLanguageVectors(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{
			name:    "empty payload",
			payload: map[string]any{},
			want:    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
		{
			name:    "nil payload is treated as empty",
			payload: nil,
			want:    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ContentHash(tc.payload)
			if err != nil {
				t.Fatalf("ContentHash: %v", err)
			}
			if got != tc.want {
				t.Fatalf("hash = %s, want %s", got, tc.want)
			}
		})
	}
}

// Key order in a Go map is randomized per iteration, so this is the property
// that actually makes the heartbeat comparison meaningful rather than flaky.
func TestContentHashIsStableAcrossMapOrdering(t *testing.T) {
	payload := map[string]any{
		"manufacturer": "Contoso",
		"model":        "X1",
		"serial":       "SN-1",
		"bios_vendor":  "Contoso",
		"bios_version": "1.2.3",
	}
	first, err := ContentHash(payload)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	for i := 0; i < 50; i++ {
		again, err := ContentHash(payload)
		if err != nil {
			t.Fatalf("ContentHash: %v", err)
		}
		if again != first {
			t.Fatalf("hash changed between runs: %s != %s", again, first)
		}
	}
}

func TestContentHashDistinguishesAbsentFromEmpty(t *testing.T) {
	// "we could not read the serial" and "the serial is empty" must not
	// collapse to the same digest, or a real hardware change would go unnoticed.
	absent, err := ContentHash(map[string]any{"model": "X1"})
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	empty, err := ContentHash(map[string]any{"model": "X1", "serial": ""})
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if absent == empty {
		t.Fatal("absent and empty-string fields produced the same hash")
	}
}

func TestHashesSkipsSectionsThatCannotBeEncoded(t *testing.T) {
	sections := []Section{
		{Section: SectionSystem, Payload: map[string]any{"model": "X1"}},
		// A channel cannot be marshalled; the section is omitted rather than
		// advertised with a wrong digest, which the server would read as
		// "unchanged" and never request.
		{Section: SectionCPU, Payload: map[string]any{"bad": make(chan int)}},
	}
	hashes := Hashes(sections)
	if _, ok := hashes[SectionSystem]; !ok {
		t.Fatal("expected the encodable section to be advertised")
	}
	if _, ok := hashes[SectionCPU]; ok {
		t.Fatal("expected the unencodable section to be omitted")
	}
}

func TestSelectReturnsRequestedSectionsInCollectionOrder(t *testing.T) {
	sections := []Section{
		{Section: SectionSystem},
		{Section: SectionCPU},
		{Section: SectionMemory},
	}
	got := Select(sections, []string{SectionMemory, SectionSystem})
	if len(got) != 2 {
		t.Fatalf("expected 2 sections, got %d", len(got))
	}
	if got[0].Section != SectionSystem || got[1].Section != SectionMemory {
		t.Fatalf("collection order not preserved: %s, %s", got[0].Section, got[1].Section)
	}
}

func TestSelectIgnoresUnknownAndEmptyRequests(t *testing.T) {
	sections := []Section{{Section: SectionSystem}}
	if got := Select(sections, nil); got != nil {
		t.Fatalf("expected nil for an empty request, got %v", got)
	}
	// The server can only ask for what was advertised; a name the agent cannot
	// produce is ignored rather than provoking an empty-section upload loop.
	if got := Select(sections, []string{"installed_software"}); len(got) != 0 {
		t.Fatalf("expected no sections for an unknown name, got %d", len(got))
	}
}

func TestUnsupportedPlatformReportsEverySectionExplicitly(t *testing.T) {
	sections := unsupportedSections(time.Now().UTC())
	if len(sections) != len(AllSections) {
		t.Fatalf("expected %d sections, got %d", len(AllSections), len(sections))
	}
	for _, section := range sections {
		if section.Status != StatusUnsupported {
			t.Fatalf("%s: status = %s, want %s", section.Section, section.Status, StatusUnsupported)
		}
		// An empty payload with an "ok" status would read as "this machine has
		// no disks"; the status is what keeps it honest.
		if len(section.Payload) != 0 {
			t.Fatalf("%s: expected an empty payload", section.Section)
		}
	}
}

func TestSubmissionSerializesToTheServerContract(t *testing.T) {
	encoded, err := json.Marshal(Submission{
		InventorySchemaVersion: SchemaVersion,
		AgentVersion:           "0.1.2",
		Sections: []Section{{
			Section:     SectionSystem,
			Status:      StatusOK,
			CollectedAt: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
			Payload:     map[string]any{"model": "X1"},
		}},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"inventory_schema_version":1,"agent_version":"0.1.2","sections":` +
		`[{"section":"system","status":"ok","collected_at":"2026-07-30T12:00:00Z",` +
		`"payload":{"model":"X1"}}]}`
	if string(encoded) != want {
		t.Fatalf("submission wire format changed:\n got: %s\nwant: %s", encoded, want)
	}
}
