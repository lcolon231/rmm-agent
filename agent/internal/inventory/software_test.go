// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func names(entries []map[string]any) []string {
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, _ := entry["name"].(string)
		out = append(out, name)
	}
	return out
}

func TestNormalizeDropsRowsWithoutADisplayName(t *testing.T) {
	entries := NormalizeSoftware([]RawSoftware{
		{Name: "7-Zip", Source: "machine_x64"},
		{Name: "   ", Source: "machine_x64"},
		{Name: "", Source: "machine_x86"},
	})
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d: %v", len(entries), names(entries))
	}
}

func TestNormalizeDedupesAcrossRegistryViewsByPrecedence(t *testing.T) {
	// The same program registered in every view must be reported once, from
	// the native machine view.
	entries := NormalizeSoftware([]RawSoftware{
		{Name: "Contoso Agent", Version: "1.0", Source: "user"},
		{Name: "Contoso Agent", Version: "1.0", Source: "machine_x86"},
		{Name: "Contoso Agent", Version: "1.0", Source: "machine_x64"},
	})
	if len(entries) != 1 {
		t.Fatalf("expected 1 deduped entry, got %d", len(entries))
	}
	if entries[0]["architecture"] != ArchX64 {
		t.Fatalf("architecture = %v, want %s", entries[0]["architecture"], ArchX64)
	}
	if entries[0]["scope"] != ScopeMachine {
		t.Fatalf("scope = %v, want %s", entries[0]["scope"], ScopeMachine)
	}
}

func TestNormalizeDedupeIgnoresCaseAndSpacingButNotVersion(t *testing.T) {
	entries := NormalizeSoftware([]RawSoftware{
		{Name: "7-Zip", Version: "23.01", Source: "machine_x64"},
		{Name: "7-zip  ", Version: "23.01", Source: "machine_x86"},
		// A second installed major version is a distinct program, not a dupe.
		{Name: "7-Zip", Version: "22.00", Source: "machine_x64"},
	})
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d: %v", len(entries), entries)
	}
}

func TestNormalizeSortsDeterministicallyForStableHashing(t *testing.T) {
	// Registry enumeration order is not stable between runs. If the payload
	// were unsorted its content hash would change every collection and an
	// unchanged machine would re-upload its software list forever.
	rows := []RawSoftware{
		{Name: "Zeta", Version: "1", Source: "machine_x64"},
		{Name: "alpha", Version: "2", Source: "machine_x64"},
		{Name: "Alpha", Version: "1", Source: "machine_x86"},
		{Name: "middle", Version: "1", Source: "user"},
	}
	first := NormalizeSoftware(rows)
	for i := 0; i < 25; i++ {
		again := NormalizeSoftware(rows)
		if strings.Join(names(again), "|") != strings.Join(names(first), "|") {
			t.Fatalf("ordering changed between runs:\n%v\n%v", names(first), names(again))
		}
	}
	got := names(first)
	want := []string{"Alpha", "alpha", "middle", "Zeta"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestInstallDateIsOnlyReportedWhenItParsesCleanly(t *testing.T) {
	entries := NormalizeSoftware([]RawSoftware{
		{Name: "Good", InstallDate: "20260314", Source: "machine_x64"},
		{Name: "Malformed", InstallDate: "14/03/2026", Source: "machine_x64"},
		{Name: "Empty", InstallDate: "", Source: "machine_x64"},
		{Name: "Nonsense", InstallDate: "abcdefgh", Source: "machine_x64"},
		{Name: "OutOfRange", InstallDate: "20261345", Source: "machine_x64"},
	})
	byName := map[string]map[string]any{}
	for _, entry := range entries {
		byName[entry["name"].(string)] = entry
	}
	if got := byName["Good"]["install_date"]; got != "2026-03-14T00:00:00Z" {
		t.Fatalf("install_date = %v", got)
	}
	// A guessed date is worse than no date.
	for _, name := range []string{"Malformed", "Empty", "Nonsense", "OutOfRange"} {
		if _, present := byName[name]["install_date"]; present {
			t.Fatalf("%s should not report an install_date", name)
		}
	}
}

func TestAbsentOptionalFieldsAreOmittedNotEmptied(t *testing.T) {
	entries := NormalizeSoftware([]RawSoftware{
		{Name: "Bare", Source: "machine_x64"},
	})
	for _, key := range []string{"version", "publisher", "identifier", "install_date"} {
		if _, present := entries[0][key]; present {
			t.Fatalf("%s should be omitted when not reported", key)
		}
	}
}

func TestPerUserRegistrationsDoNotClaimAnArchitecture(t *testing.T) {
	entries := NormalizeSoftware([]RawSoftware{{Name: "UserApp", Source: "user"}})
	if entries[0]["architecture"] != ArchUnknown {
		t.Fatalf("architecture = %v, want %s", entries[0]["architecture"], ArchUnknown)
	}
	if entries[0]["scope"] != ScopeUser {
		t.Fatalf("scope = %v, want %s", entries[0]["scope"], ScopeUser)
	}
}

// The load-bearing test: a count cap alone is not enough, because at the
// server's field bounds ~250 entries already exceed the byte cap. Without
// fitting to bytes the server would reject every submission from a machine
// like this and it would silently never report software at all.
func TestOversizedEntriesAreFitToTheByteBudgetNotJustTheCountCap(t *testing.T) {
	rows := make([]RawSoftware, 0, 600)
	for i := 0; i < 600; i++ {
		rows = append(rows, RawSoftware{
			Name:       strings.Repeat("n", 200) + string(rune('a'+i%26)) + itoa(i),
			Version:    strings.Repeat("v", 200),
			Publisher:  strings.Repeat("p", 200),
			Identifier: strings.Repeat("i", 100),
			Source:     "machine_x64",
		})
	}

	payload, trimmed := FitSoftwareEntries(NormalizeSoftware(rows))
	if !trimmed {
		t.Fatal("expected the payload to be reported as trimmed")
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(encoded) > MaxSectionBytes {
		t.Fatalf("payload is %d bytes, over the %d cap the server enforces",
			len(encoded), MaxSectionBytes)
	}
	entries, _ := payload["entries"].([]map[string]any)
	if len(entries) == 0 {
		t.Fatal("expected some entries to survive trimming")
	}
	// Under 600 rows the byte budget must bind before the count ceiling.
	if len(entries) >= MaxSoftwareEntries {
		t.Fatalf("expected the byte budget to bind, kept %d", len(entries))
	}
}

func TestOrdinarySoftwareListsAreNotTrimmed(t *testing.T) {
	rows := make([]RawSoftware, 0, 300)
	for i := 0; i < 300; i++ {
		rows = append(rows, RawSoftware{
			Name:      "Program " + itoa(i),
			Version:   "1.2.3",
			Publisher: "Contoso Corporation",
			Source:    "machine_x64",
		})
	}
	payload, trimmed := FitSoftwareEntries(NormalizeSoftware(rows))
	if trimmed {
		t.Fatal("a 300-program machine should fit without trimming")
	}
	entries, _ := payload["entries"].([]map[string]any)
	if len(entries) != 300 {
		t.Fatalf("kept %d entries, want 300", len(entries))
	}
}

func TestSoftwareSectionReportsPartialOnlyWhenBounded(t *testing.T) {
	now := time.Now().UTC()
	small := SoftwareSection([]RawSoftware{{Name: "One", Source: "machine_x64"}}, now)
	if small.Status != StatusOK {
		t.Fatalf("status = %s, want %s", small.Status, StatusOK)
	}
	if small.Section != SectionInstalledSoftware {
		t.Fatalf("section = %s", small.Section)
	}

	rows := make([]RawSoftware, 0, MaxSoftwareEntries+50)
	for i := 0; i < MaxSoftwareEntries+50; i++ {
		rows = append(rows, RawSoftware{Name: "P" + itoa(i), Source: "machine_x64"})
	}
	big := SoftwareSection(rows, now)
	if big.Status != StatusPartial {
		t.Fatalf("status = %s, want %s", big.Status, StatusPartial)
	}
}

func TestSoftwarePayloadHashesStablyAcrossRuns(t *testing.T) {
	rows := []RawSoftware{
		{Name: "Beta", Version: "2", Source: "machine_x86"},
		{Name: "Alpha", Version: "1", Source: "machine_x64"},
	}
	first, err := ContentHash(SoftwareSection(rows, time.Now().UTC()).Payload)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := ContentHash(SoftwareSection(rows, time.Now().UTC()).Payload)
		if err != nil {
			t.Fatalf("ContentHash: %v", err)
		}
		if again != first {
			t.Fatalf("hash changed between runs: %s != %s", again, first)
		}
	}
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := ""
	for value > 0 {
		digits = string(rune('0'+value%10)) + digits
		value /= 10
	}
	return digits
}
