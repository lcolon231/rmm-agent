// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type hashVector struct {
	Name          string `json:"name"`
	PayloadJSON   string `json:"payload_json"`
	CanonicalJSON string `json:"canonical_json"`
	SHA256        string `json:"sha256"`
}

func loadHashVectors(t *testing.T) []hashVector {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/test-vectors/inventory-hash-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Valid []hashVector `json:"valid"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Valid) == 0 {
		t.Fatal("inventory-hash-v1 has no vectors")
	}
	return file.Valid
}

// typedVectorValue gives vector numbers the types collectors produce:
// normalized integer fields are int64 and everything else stays float64.
func typedVectorValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, item := range typed {
			typed[key] = typedVectorValue(item)
		}
	case []any:
		for i, item := range typed {
			typed[i] = typedVectorValue(item)
		}
	case json.Number:
		if n, err := typed.Int64(); err == nil {
			return n
		}
		f, _ := typed.Float64()
		return f
	}
	return value
}

// The shared vectors pin the exact bytes and digest. The server asserts the
// same file in server/tests/test_inventory.py, so a canonicalization drift on
// either side breaks a test instead of making every section resend forever.
func TestContentHashMatchesSharedCrossLanguageVectors(t *testing.T) {
	for _, tc := range loadHashVectors(t) {
		t.Run(tc.Name, func(t *testing.T) {
			dec := json.NewDecoder(strings.NewReader(tc.PayloadJSON))
			dec.UseNumber()
			var payload map[string]any
			if err := dec.Decode(&payload); err != nil {
				t.Fatalf("decode payload_json: %v", err)
			}
			payload = typedVectorValue(payload).(map[string]any)

			encoded, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(encoded) != tc.CanonicalJSON {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", encoded, tc.CanonicalJSON)
			}
			sum := sha256.Sum256([]byte(tc.CanonicalJSON))
			if hex.EncodeToString(sum[:]) != tc.SHA256 {
				t.Fatalf("vector sha256 does not match its own canonical_json")
			}
			got, err := ContentHash(payload)
			if err != nil {
				t.Fatalf("ContentHash: %v", err)
			}
			if got != tc.SHA256 {
				t.Fatalf("hash = %s, want %s", got, tc.SHA256)
			}
		})
	}
}

func TestContentHashTreatsNilPayloadAsEmpty(t *testing.T) {
	got, err := ContentHash(nil)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	want, err := ContentHash(map[string]any{})
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	if got != want {
		t.Fatalf("nil payload hash = %s, want empty-payload hash %s", got, want)
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
