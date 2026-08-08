// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/inventory"
)

func sampleMissing() []map[string]any {
	return []map[string]any{
		{
			"title":           "2026-08 Cumulative Update for Windows 11 (KB5034123)",
			"kb_id":           "KB5034123",
			"update_id":       "12345678-1234-1234-1234-1234567890ab",
			"classification":  "Security Updates",
			"product":         "Windows 11",
			"severity":        "Critical",
			"reboot_required": true,
			"is_downloaded":   false,
			"support_url":     "https://support.microsoft.com/kb/5034123",
			// An unexpected field the collector might emit must be dropped, or the
			// server's extra="forbid" model would reject the whole submission.
			"secret_note": "should not survive",
		},
	}
}

func TestBuildSectionNormalizesAndAllowlists(t *testing.T) {
	reboot := true
	section, summary := BuildSection(
		sampleMissing(),
		[]map[string]any{{"kb_id": "KB5030211", "installed_on": "2026-07-01T00:00:00Z"}},
		time.Date(2026, 8, 8, 0, 0, 0, 0, time.UTC),
		&reboot,
		"",
		"",
	)
	if section.Section != SectionWindowsUpdates || section.Status != inventory.StatusOK {
		t.Fatalf("unexpected section head: %+v", section)
	}
	missing, _ := section.Payload["missing"].([]map[string]any)
	if len(missing) != 1 {
		t.Fatalf("missing len = %d, want 1", len(missing))
	}
	if _, leaked := missing[0]["secret_note"]; leaked {
		t.Fatal("non-allowlisted field survived normalization")
	}
	if missing[0]["kb_id"] != "KB5034123" || missing[0]["severity"] != "Critical" {
		t.Fatalf("allowlisted fields lost: %+v", missing[0])
	}
	if missing[0]["priority_grade"] != "P1 - Critical" {
		t.Fatalf("priority_grade want 'P1 - Critical', got: %+v", missing[0]["priority_grade"])
	}
	if section.Payload["reboot_required"] != true {
		t.Fatalf("system reboot_required not carried: %+v", section.Payload["reboot_required"])
	}
	if summary.MissingCount != 1 || summary.InstalledCount != 1 || summary.Status != inventory.StatusOK {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestCalculatePriorityGrade(t *testing.T) {
	tests := []struct {
		severity       string
		classification string
		reboot         bool
		want           string
	}{
		{"Critical", "Security Updates", true, "P1 - Critical"},
		{"Critical", "Updates", false, "P1 - Critical"},
		{"Important", "Security Updates", false, "P2 - High"},
		{"", "Security Updates", false, "P2 - High"},
		{"Moderate", "Updates", false, "P3 - Medium"},
		{"Low", "Service Packs", false, "P3 - Medium"},
		{"", "Feature Packs", false, "P4 - Low"},
		{"", "Definition Updates", false, "P4 - Low"},
	}
	for _, tt := range tests {
		got := CalculatePriorityGrade(tt.severity, tt.classification, tt.reboot)
		if got != tt.want {
			t.Errorf("CalculatePriorityGrade(%q, %q, %v) = %q, want %q",
				tt.severity, tt.classification, tt.reboot, got, tt.want)
		}
	}
}

func TestBuildSectionDropsTitlelessMissing(t *testing.T) {
	rows := []map[string]any{
		{"kb_id": "KB1"},              // no title -> dropped
		{"title": "", "kb_id": "KB2"}, // empty title -> dropped
		{"title": "Real Update", "kb_id": "KB3"},
	}
	section, summary := BuildSection(rows, nil, time.Now(), nil, "", "")
	missing, _ := section.Payload["missing"].([]map[string]any)
	if len(missing) != 1 || missing[0]["kb_id"] != "KB3" {
		t.Fatalf("titleless rows not dropped: %+v", missing)
	}
	if summary.MissingCount != 1 {
		t.Fatalf("summary missing count = %d, want 1", summary.MissingCount)
	}
}

func TestBuildSectionTrimsOverCapAndReportsPartial(t *testing.T) {
	rows := make([]map[string]any, MaxMissingUpdates+5)
	for i := range rows {
		rows[i] = map[string]any{"title": "Update", "kb_id": "KB"}
	}
	section, summary := BuildSection(rows, nil, time.Now(), nil, "", "")
	missing, _ := section.Payload["missing"].([]map[string]any)
	if len(missing) != MaxMissingUpdates {
		t.Fatalf("missing not trimmed to cap: got %d", len(missing))
	}
	if section.Status != inventory.StatusPartial || !summary.Truncated {
		t.Fatalf("over-cap must report partial+truncated: status=%s trunc=%v", section.Status, summary.Truncated)
	}
}

func TestBuildSectionErrorCodeIsUnavailable(t *testing.T) {
	section, summary := BuildSection(nil, []map[string]any{{"kb_id": "KB1"}}, time.Now(), nil, "0x8024402c", "")
	if section.Status != inventory.StatusUnavailable || summary.Status != inventory.StatusUnavailable {
		t.Fatalf("error_code must mark section unavailable: %s", section.Status)
	}
	if section.Payload["error_code"] != "0x8024402c" {
		t.Fatalf("error_code not carried: %+v", section.Payload["error_code"])
	}
}

func TestBuildSectionHistoryErrorIsPartialAndPreservesMissing(t *testing.T) {
	section, summary := BuildSection(
		[]map[string]any{{"title": "Driver update", "update_id": "12345678-1234-1234-1234-1234567890ab"}},
		nil,
		time.Now(),
		nil,
		"",
		"0x8024000C",
	)
	if section.Status != inventory.StatusPartial || summary.Status != inventory.StatusPartial {
		t.Fatalf("history error must mark a usable scan partial: %s", section.Status)
	}
	if summary.MissingCount != 1 || summary.HistoryErrorCode != "0x8024000C" {
		t.Fatalf("missing scan or history error lost: %+v", summary)
	}
}

func TestUnsupportedSection(t *testing.T) {
	section, summary := UnsupportedSection()
	if section.Section != SectionWindowsUpdates || section.Status != inventory.StatusUnsupported {
		t.Fatalf("unexpected unsupported section: %+v", section)
	}
	if summary.Status != inventory.StatusUnsupported {
		t.Fatalf("unexpected unsupported summary: %+v", summary)
	}
}
