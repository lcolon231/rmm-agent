// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

type fakeProbe struct {
	diskValue     float64
	diskOK        bool
	serviceState  string
	serviceOK     bool
	rebootPending bool
	rebootOK      bool
}

func (p fakeProbe) DiskPercent(context.Context, string) (float64, bool, string) {
	return p.diskValue, p.diskOK, "fake_disk"
}
func (p fakeProbe) ServiceState(context.Context, string) (string, bool, string) {
	return p.serviceState, p.serviceOK, "fake_service"
}
func (p fakeProbe) RebootPending(context.Context) (bool, bool, string) {
	return p.rebootPending, p.rebootOK, "fake_reboot"
}

func number(value float64) *float64 { return &value }

func assignment(key, kind string) Assignment {
	return Assignment{
		PolicyID:         "policy-1",
		PolicyRevisionID: "revision-1",
		Definition: Definition{
			Key:      key,
			Type:     kind,
			Enabled:  true,
			Schedule: Schedule{IntervalSeconds: 30},
			Threshold: &Threshold{
				Op:       "gte",
				Warning:  number(80),
				Critical: number(90),
			},
			Hysteresis: Hysteresis{RaiseSamples: 2, ClearSamples: 2},
			Params:     map[string]any{},
		},
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := LoadStore(filepath.Join(t.TempDir(), "monitoring_state.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestEvaluatorCadenceHysteresisAndDurableOutbox(t *testing.T) {
	store := newTestStore(t)
	evaluator := NewEvaluator(store, fakeProbe{})
	check := assignment("cpu", "cpu")
	start := time.Date(2026, 8, 2, 5, 0, 0, 0, time.UTC)
	sample := telemetry.Sample{CPUPercent: 95, CPUAvailable: true, CollectedAt: start}

	if count, err := evaluator.Evaluate(context.Background(), []Assignment{check}, sample, start); err != nil || count != 1 {
		t.Fatalf("first evaluation count=%d err=%v", count, err)
	}
	if got := store.Pending[0].Status; got != "unknown" {
		t.Fatalf("first alarm should be pending, got %q", got)
	}
	if err := store.AcknowledgePrefix(1); err != nil {
		t.Fatal(err)
	}
	if count, err := evaluator.Evaluate(context.Background(), []Assignment{check}, sample, start.Add(10*time.Second)); err != nil || count != 0 {
		t.Fatalf("cadence count=%d err=%v", count, err)
	}
	sample.CollectedAt = start.Add(31 * time.Second)
	if count, err := evaluator.Evaluate(context.Background(), []Assignment{check}, sample, sample.CollectedAt); err != nil || count != 1 {
		t.Fatalf("second evaluation count=%d err=%v", count, err)
	}
	if got := store.Pending[0].Status; got != "critical" {
		t.Fatalf("second alarm status=%q", got)
	}
	if err := store.AcknowledgePrefix(1); err != nil {
		t.Fatal(err)
	}

	sample.CPUPercent = 10
	sample.CollectedAt = start.Add(62 * time.Second)
	_, _ = evaluator.Evaluate(context.Background(), []Assignment{check}, sample, sample.CollectedAt)
	if got := store.Pending[0].Status; got != "critical" {
		t.Fatalf("first clear should remain critical, got %q", got)
	}
	_ = store.AcknowledgePrefix(1)
	sample.CollectedAt = start.Add(93 * time.Second)
	_, _ = evaluator.Evaluate(context.Background(), []Assignment{check}, sample, sample.CollectedAt)
	if got := store.Pending[0].Status; got != "ok" {
		t.Fatalf("second clear status=%q", got)
	}

	reloaded, err := LoadStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Pending) != 1 || reloaded.Pending[0].ID != store.Pending[0].ID {
		t.Fatal("pending result was not durably restored")
	}
}

func TestEvaluatorUnavailableStateChecksAndStaleSamples(t *testing.T) {
	store := newTestStore(t)
	evaluator := NewEvaluator(store, fakeProbe{
		diskValue:     97,
		diskOK:        true,
		serviceState:  "stopped",
		serviceOK:     true,
		rebootPending: true,
		rebootOK:      true,
	})
	now := time.Date(2026, 8, 2, 6, 0, 0, 0, time.UTC)
	cpu := assignment("cpu", "cpu")
	cpu.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}
	disk := assignment("data", "disk")
	disk.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}
	disk.Definition.Params = map[string]any{"mount_point": "D:"}
	service := assignment("spooler", "service")
	service.Definition.Threshold = nil
	service.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}
	service.Definition.Params = map[string]any{"service_name": "Spooler"}
	reboot := assignment("reboot", "reboot_pending")
	reboot.Definition.Threshold = nil
	reboot.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}

	sample := telemetry.Sample{CPUPercent: 10, CPUAvailable: true, CollectedAt: now.Add(-10 * time.Minute)}
	count, err := evaluator.Evaluate(context.Background(), []Assignment{cpu, disk, service, reboot}, sample, now)
	if err != nil || count != 4 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	byKey := map[string]Result{}
	for _, result := range store.Pending {
		byKey[result.CheckKey] = result
	}
	if byKey["cpu"].Status != "unknown" || byKey["cpu"].Detail["reason"] != "sample_stale" {
		t.Fatalf("unexpected stale CPU result: %#v", byKey["cpu"])
	}
	if byKey["data"].Status != "critical" || byKey["spooler"].Status != "critical" || byKey["reboot"].Status != "critical" {
		t.Fatalf("unexpected state results: %#v", byKey)
	}
}

func TestEvaluatorCPUOnlyMemoryAndSystemDiskSamples(t *testing.T) {
	store := newTestStore(t)
	evaluator := NewEvaluator(store, fakeProbe{})
	now := time.Date(2026, 8, 2, 7, 0, 0, 0, time.UTC)
	cpu := assignment("cpu", "cpu")
	memory := assignment("memory", "memory")
	disk := assignment("system-disk", "disk")
	for _, check := range []*Assignment{&cpu, &memory, &disk} {
		check.Definition.Hysteresis = Hysteresis{RaiseSamples: 1, ClearSamples: 1}
	}
	disk.Definition.Params = map[string]any{"mount_point": "C:"}
	sample := telemetry.Sample{
		CPUPercent:    95,
		MemPercent:    85,
		DiskPercent:   70,
		CPUAvailable:  true,
		MemAvailable:  true,
		DiskAvailable: true,
		CollectedAt:   now,
	}
	count, err := evaluator.Evaluate(context.Background(), []Assignment{cpu, memory, disk}, sample, now)
	if err != nil || count != 3 {
		t.Fatalf("count=%d err=%v", count, err)
	}
	byKey := map[string]string{}
	for _, result := range store.Pending {
		byKey[result.CheckKey] = result.Status
	}
	if byKey["cpu"] != "critical" || byKey["memory"] != "warning" || byKey["system-disk"] != "ok" {
		t.Fatalf("unexpected numeric statuses: %#v", byKey)
	}
}

func TestEvaluatorDropsResultsFromSupersededAssignments(t *testing.T) {
	store := newTestStore(t)
	now := time.Date(2026, 8, 2, 8, 0, 0, 0, time.UTC)
	store.Pending = []Result{{
		ID:               "00000000000000000000000000000000",
		PolicyID:         "policy-1",
		PolicyRevisionID: "revision-old",
		CheckKey:         "cpu",
		Status:           "ok",
		EvaluatedAt:      now.Add(-time.Minute),
	}}
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}

	check := assignment("cpu", "cpu")
	check.PolicyRevisionID = "revision-new"
	sample := telemetry.Sample{CPUPercent: 10, CPUAvailable: true, CollectedAt: now}
	if _, err := NewEvaluator(store, fakeProbe{}).Evaluate(context.Background(), []Assignment{check}, sample, now); err != nil {
		t.Fatal(err)
	}
	if len(store.Pending) != 1 || store.Pending[0].PolicyRevisionID != "revision-new" {
		t.Fatalf("superseded result was not replaced: %#v", store.Pending)
	}

	reloaded, err := LoadStore(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.Pending) != 1 || reloaded.Pending[0].PolicyRevisionID != "revision-new" {
		t.Fatalf("reconciled outbox was not durable: %#v", reloaded.Pending)
	}
}
