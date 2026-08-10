// SPDX-License-Identifier: AGPL-3.0-only
package eventlog

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

func withFakeQuery(t *testing.T, fn func(ctx context.Context, channel, xpath string, limit int) ([]Record, error)) {
	original := runQuery
	runQuery = fn
	t.Cleanup(func() { runQuery = original })
}

func TestBuildXPathIncludesBoundsAndFilters(t *testing.T) {
	xpath := buildXPath(queryPayload{
		Channel:           "Security",
		TimeWindowSeconds: 3600,
		MaxEvents:         10,
		Levels:            []int{2, 3},
		EventIDs:          []int{4624},
		Providers:         []string{"Microsoft-Windows-Security-Auditing"},
		Cursor:            42,
	})
	for _, want := range []string{
		"timediff(@SystemTime) <= 3600000",
		"(Level=2 or Level=3)",
		"(EventID=4624)",
		"Provider[@Name='Microsoft-Windows-Security-Auditing']",
		"EventRecordID > 42",
	} {
		if !strings.Contains(xpath, want) {
			t.Fatalf("xpath %q missing %q", xpath, want)
		}
	}
}

func TestExecuteReturnsMetadataAndPaginates(t *testing.T) {
	withFakeQuery(t, func(_ context.Context, channel, _ string, limit int) ([]Record, error) {
		// Return a full page (max_events+1) so has_more is set and the extra is trimmed.
		records := make([]Record, 0, limit)
		for i := 1; i <= limit; i++ {
			records = append(records, Record{RecordID: int64(i), Provider: "X", EventID: 1000, Level: 4, Channel: channel})
		}
		return records, nil
	})
	raw, _ := json.Marshal(map[string]any{"channel": "System", "tier_ack": false, "time_window_seconds": 3600, "max_events": 2})
	res := Execute(context.Background(), executor.KindQueryEventLog, raw)
	if res.ExitCode != 0 {
		t.Fatalf("unexpected exit: %+v", res)
	}
	var out Result
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || out.Count != 2 || !out.HasMore || out.NextCursor != 2 {
		t.Fatalf("unexpected result: %+v", out)
	}
	if strings.Contains(res.Stdout, "EventData") || strings.Contains(res.Stdout, "message") {
		t.Fatalf("metadata-only result must carry no message body: %s", res.Stdout)
	}
}

func TestExecuteRejectsWrongKindAndUnsafeProvider(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"channel": "System", "time_window_seconds": 3600, "max_events": 2})
	if res := Execute(context.Background(), "reboot", raw); res.ExitCode == 0 {
		t.Fatal("a non-event-log kind must be refused")
	}
	// A provider containing a quote is refused before any platform call.
	badRaw, _ := json.Marshal(map[string]any{"channel": "System", "time_window_seconds": 3600, "max_events": 2, "providers": []string{"a'b"}})
	if res := Execute(context.Background(), executor.KindQueryEventLog, badRaw); res.ExitCode == 0 {
		t.Fatal("a provider containing a quote must be refused")
	}
}
