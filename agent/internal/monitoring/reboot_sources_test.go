// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

func TestRebootProbeOutputReportsEachSourceIndependently(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		sources RebootSources
	}{
		{"none", "false\nfalse\nfalse\n-1", RebootSources{}},
		{"servicing only", "true\nfalse\nfalse\n-1", RebootSources{ComponentBasedServicing: true}},
		{"windows update only", "false\ntrue\nfalse\n-1", RebootSources{WindowsUpdate: true}},
		{"file rename only", "false\nfalse\ntrue\n3", RebootSources{PendingFileRename: true}},
		{"all three", "true\ntrue\ntrue\n1", RebootSources{
			ComponentBasedServicing: true, WindowsUpdate: true, PendingFileRename: true,
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			status, ok := parseRebootProbeOutput(testCase.out)
			if !ok {
				t.Fatalf("parse failed for %q", testCase.out)
			}
			if status.Sources != testCase.sources {
				t.Fatalf("sources = %#v, want %#v", status.Sources, testCase.sources)
			}
			if status.Sources.Any() != (testCase.sources != RebootSources{}) {
				t.Fatalf("Any() disagrees with the source flags: %#v", status)
			}
		})
	}
}

func TestRebootProbeOutputTreatsTheCountAsBestEffort(t *testing.T) {
	// A count the query could not produce leaves the reading usable: the
	// presence flags stay the authority for status.
	for _, out := range []string{
		"false\nfalse\ntrue\n-1",
		"false\nfalse\ntrue\nnot-a-number",
	} {
		status, ok := parseRebootProbeOutput(out)
		if !ok || status.CountKnown || !status.Sources.PendingFileRename {
			t.Fatalf("output %q produced %#v ok=%v", out, status, ok)
		}
		if _, present := status.Detail()["pending_file_rename_count"]; present {
			t.Fatalf("an unknown count must be omitted, not reported as zero: %#v", status.Detail())
		}
	}

	status, ok := parseRebootProbeOutput("false\r\nfalse\r\ntrue\r\n4\r\n")
	if !ok || !status.CountKnown || status.PendingFileRenameCount != 4 {
		t.Fatalf("CRLF output produced %#v ok=%v", status, ok)
	}
}

func TestRebootProbeOutputRejectsUnreadableSources(t *testing.T) {
	for _, out := range []string{"", "true\nfalse", "yes\nno\nmaybe\n0", "true\nfalse\nfalse\n0\nextra"} {
		if status, ok := parseRebootProbeOutput(out); ok {
			t.Fatalf("output %q should not parse, got %#v", out, status)
		}
	}
}

// The registry value behind the count lists file paths that routinely contain
// user names. Result detail is meant to stay safe to forward to alert email and
// third-party webhooks, so no code path may return one.
func TestRebootProbeNeverReturnsFilePaths(t *testing.T) {
	status, ok := parseRebootProbeOutput("true\ntrue\ntrue\n7")
	if !ok {
		t.Fatal("parse failed")
	}
	encoded, err := json.Marshal(status.Detail())
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`\\`, ":\\", "C:", "Users", "/"} {
		if strings.Contains(string(encoded), fragment) {
			t.Fatalf("detail %s contains path-like fragment %q", encoded, fragment)
		}
	}
	// Every reported field is a bool or the count itself.
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	sources, _ := decoded["sources"].(map[string]any)
	if len(sources) != 3 {
		t.Fatalf("unexpected sources payload: %#v", decoded)
	}
	for key, value := range sources {
		if _, isBool := value.(bool); !isBool {
			t.Fatalf("source %q is not a boolean: %#v", key, value)
		}
	}
	if decoded["pending_file_rename_count"] != float64(7) {
		t.Fatalf("unexpected count: %#v", decoded["pending_file_rename_count"])
	}
}

func rebootAssignment() Assignment {
	check := assignment("reboot", "reboot_pending")
	check.Definition.Threshold = nil
	check.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}
	return check
}

// Reporting the sources must not move any status. Pending stays critical, any
// source set is still pending, and a probe failure is still unknown carrying
// the probe's own reason (reboot_probe_failed on Windows) unchanged.
func TestRebootSourcesDoNotMoveCheckStatus(t *testing.T) {
	cases := []struct {
		name   string
		probe  fakeProbe
		status string
		reason string
	}{
		{"servicing only", fakeProbe{
			rebootStatus: RebootStatus{Sources: RebootSources{ComponentBasedServicing: true}},
			rebootOK:     true,
		}, "critical", "reboot_pending"},
		{"windows update only", fakeProbe{
			rebootStatus: RebootStatus{Sources: RebootSources{WindowsUpdate: true}},
			rebootOK:     true,
		}, "critical", "reboot_pending"},
		{"file rename only", fakeProbe{
			rebootStatus: RebootStatus{
				Sources:                RebootSources{PendingFileRename: true},
				PendingFileRenameCount: 5,
				CountKnown:             true,
			},
			rebootOK: true,
		}, "critical", "reboot_pending"},
		{"all three", fakeProbe{
			rebootStatus: RebootStatus{Sources: RebootSources{
				ComponentBasedServicing: true, WindowsUpdate: true, PendingFileRename: true,
			}},
			rebootOK: true,
		}, "critical", "reboot_pending"},
		{"none set", fakeProbe{rebootOK: true}, "ok", "reboot_not_pending"},
		{"probe failed", fakeProbe{}, "unknown", "fake_reboot"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			store := newTestStore(t)
			evaluator := NewEvaluator(store, testCase.probe)
			now := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
			count, err := evaluator.Evaluate(
				context.Background(),
				[]Assignment{rebootAssignment()},
				telemetry.Sample{CollectedAt: now},
				now,
			)
			if err != nil || count != 1 {
				t.Fatalf("count=%d err=%v", count, err)
			}
			result := store.Pending[0]
			if result.Status != testCase.status || result.Detail["reason"] != testCase.reason {
				t.Fatalf("status=%q reason=%v, want %q/%q",
					result.Status, result.Detail["reason"], testCase.status, testCase.reason)
			}
			sources, present := result.Detail["sources"]
			if !testCase.probe.rebootOK {
				if present {
					t.Fatalf("a failed probe must not report sources: %#v", result.Detail)
				}
				return
			}
			want := map[string]any{
				"component_based_servicing": testCase.probe.rebootStatus.Sources.ComponentBasedServicing,
				"windows_update":            testCase.probe.rebootStatus.Sources.WindowsUpdate,
				"pending_file_rename":       testCase.probe.rebootStatus.Sources.PendingFileRename,
			}
			encoded, _ := json.Marshal(sources)
			expected, _ := json.Marshal(want)
			if string(encoded) != string(expected) {
				t.Fatalf("sources = %s, want %s", encoded, expected)
			}
		})
	}
}

func TestRebootDetailStaysWithinTheBoundedDetailLimit(t *testing.T) {
	store := newTestStore(t)
	evaluator := NewEvaluator(store, fakeProbe{
		rebootStatus: RebootStatus{
			Sources: RebootSources{
				ComponentBasedServicing: true, WindowsUpdate: true, PendingFileRename: true,
			},
			// A pathological rename backlog still costs only an integer.
			PendingFileRenameCount: 1 << 30,
			CountKnown:             true,
		},
		rebootOK: true,
	})
	now := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	if _, err := evaluator.Evaluate(
		context.Background(),
		[]Assignment{rebootAssignment()},
		telemetry.Sample{CollectedAt: now},
		now,
	); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(store.Pending[0].Detail)
	if err != nil {
		t.Fatal(err)
	}
	// The server rejects any result detail over 16 KiB.
	if len(encoded) > 16*1024 {
		t.Fatalf("result detail is %d bytes: %s", len(encoded), encoded)
	}
}

// Only reboot checks carry the source breakdown.
func TestRebootDetailIsScopedToRebootChecks(t *testing.T) {
	store := newTestStore(t)
	evaluator := NewEvaluator(store, fakeProbe{
		rebootStatus: RebootStatus{Sources: RebootSources{WindowsUpdate: true}},
		rebootOK:     true,
	})
	now := time.Date(2026, 9, 3, 10, 0, 0, 0, time.UTC)
	cpu := assignment("cpu", "cpu")
	cpu.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}
	if _, err := evaluator.Evaluate(
		context.Background(),
		[]Assignment{cpu, rebootAssignment()},
		telemetry.Sample{CPUPercent: 10, CPUAvailable: true, CollectedAt: now},
		now,
	); err != nil {
		t.Fatal(err)
	}
	for _, result := range store.Pending {
		_, present := result.Detail["sources"]
		if present != (result.CheckKey == "reboot") {
			t.Fatalf("check %q sources present=%v", result.CheckKey, present)
		}
	}
}
