// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

const (
	maxPendingResults = 256
	maxPlatformProbes = 32
)

type Evaluator struct {
	store *Store
	probe Probe
}

func NewEvaluator(store *Store, probe Probe) *Evaluator {
	if probe == nil {
		probe = DefaultProbe()
	}
	return &Evaluator{store: store, probe: probe}
}

type probeCache struct {
	remaining int
	disks     map[string]probeNumber
	services  map[string]probeString
	reboot    *probeBool
}

type probeNumber struct {
	value  float64
	ok     bool
	reason string
}

type probeString struct {
	value  string
	ok     bool
	reason string
}

type probeBool struct {
	value  bool
	ok     bool
	reason string
}

// Evaluate appends every due result to the durable outbox before callers send
// it. Checks stop evaluating when the bounded outbox is full.
func (e *Evaluator) Evaluate(ctx context.Context, assignments []Assignment, sample telemetry.Sample, now time.Time) (int, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	active := make(map[string]Assignment, len(assignments))
	for _, assignment := range assignments {
		if assignment.Definition.Enabled {
			active[assignment.Definition.Key] = assignment
		}
	}
	dirty := false
	pending := e.store.Pending[:0]
	for _, result := range e.store.Pending {
		assignment, ok := active[result.CheckKey]
		if !ok || assignment.PolicyID != result.PolicyID || assignment.PolicyRevisionID != result.PolicyRevisionID {
			dirty = true
			continue
		}
		pending = append(pending, result)
	}
	e.store.Pending = pending
	for key := range e.store.Checks {
		assignment, ok := active[key]
		if !ok || e.store.Checks[key].PolicyRevisionID != assignment.PolicyRevisionID {
			delete(e.store.Checks, key)
			dirty = true
		}
	}

	cache := &probeCache{
		remaining: maxPlatformProbes,
		disks:     map[string]probeNumber{},
		services:  map[string]probeString{},
	}
	written := 0
	for _, assignment := range assignments {
		if !assignment.Definition.Enabled || len(e.store.Pending) >= maxPendingResults {
			continue
		}
		definition := assignment.Definition
		state := e.store.Checks[definition.Key]
		if state.PolicyRevisionID != assignment.PolicyRevisionID {
			state = CheckState{PolicyRevisionID: assignment.PolicyRevisionID}
		}
		interval := time.Duration(definition.Schedule.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 30 * time.Second
		}
		if !state.LastEvaluated.IsZero() && now.Sub(state.LastEvaluated) < interval {
			continue
		}

		raw, value, reason := e.rawStatus(ctx, cache, definition, sample, now, interval)
		stable := applyHysteresis(raw, &state, definition.Hysteresis)
		id, err := resultID()
		if err != nil {
			return written, err
		}
		state.LastEvaluated = now
		e.store.Checks[definition.Key] = state
		e.store.Pending = append(e.store.Pending, Result{
			ID:               id,
			PolicyID:         assignment.PolicyID,
			PolicyRevisionID: assignment.PolicyRevisionID,
			CheckKey:         definition.Key,
			Status:           stable,
			Value:            value,
			Detail: map[string]any{
				"check_type": definition.Type,
				"reason":     reason,
				"raw_status": raw,
				"hysteresis": map[string]any{
					"pending_status": state.PendingStatus,
					"pending_count":  state.PendingCount,
				},
			},
			EvaluatedAt: now,
		})
		written++
	}
	if written > 0 || dirty {
		if err := e.store.Save(); err != nil {
			return 0, err
		}
	}
	return written, nil
}

func (e *Evaluator) rawStatus(ctx context.Context, cache *probeCache, definition Definition, sample telemetry.Sample, now time.Time, interval time.Duration) (string, *float64, string) {
	staleAfter := 2 * interval
	if staleAfter < 2*time.Minute {
		staleAfter = 2 * time.Minute
	}
	sampleState := func(available bool, value float64) (string, *float64, string) {
		if sample.CollectedAt.IsZero() || now.Sub(sample.CollectedAt) > staleAfter {
			return "unknown", nil, "sample_stale"
		}
		if !available {
			return "unknown", nil, "sample_unavailable"
		}
		if definition.Threshold == nil {
			return "unknown", nil, "threshold_missing"
		}
		return classifyNumeric(value, *definition.Threshold), &value, "threshold_evaluated"
	}

	switch definition.Type {
	case "cpu":
		return sampleState(sample.CPUAvailable, sample.CPUPercent)
	case "memory":
		return sampleState(sample.MemAvailable, sample.MemPercent)
	case "uptime":
		return sampleState(sample.UptimeAvailable, float64(sample.UptimeSeconds))
	case "disk":
		mount, _ := definition.Params["mount_point"].(string)
		if strings.EqualFold(mount, "C:") || mount == "/" {
			return sampleState(sample.DiskAvailable, sample.DiskPercent)
		}
		probe := e.disk(ctx, cache, mount)
		if !probe.ok {
			return "unknown", nil, probe.reason
		}
		if definition.Threshold == nil {
			return "unknown", nil, "threshold_missing"
		}
		return classifyNumeric(probe.value, *definition.Threshold), &probe.value, "threshold_evaluated"
	case "service":
		name, _ := definition.Params["service_name"].(string)
		probe := e.service(ctx, cache, name)
		if !probe.ok {
			return "unknown", nil, probe.reason
		}
		value := 0.0
		if probe.value == "running" {
			value = 1
			return "ok", &value, "service_running"
		}
		if probe.value == "absent" {
			return "critical", &value, "service_absent"
		}
		return "critical", &value, "service_not_running"
	case "reboot_pending":
		probe := e.reboot(ctx, cache)
		if !probe.ok {
			return "unknown", nil, probe.reason
		}
		value := 0.0
		if probe.value {
			value = 1
			return "critical", &value, "reboot_pending"
		}
		return "ok", &value, "reboot_not_pending"
	case "offline":
		return "unknown", nil, "server_owned_check"
	default:
		return "unknown", nil, "unsupported_check_type"
	}
}

func (e *Evaluator) disk(ctx context.Context, cache *probeCache, mount string) probeNumber {
	if value, ok := cache.disks[mount]; ok {
		return value
	}
	if cache.remaining <= 0 {
		return probeNumber{reason: "probe_budget_exhausted"}
	}
	cache.remaining--
	value, ok, reason := e.probe.DiskPercent(ctx, mount)
	result := probeNumber{value: value, ok: ok, reason: reason}
	cache.disks[mount] = result
	return result
}

func (e *Evaluator) service(ctx context.Context, cache *probeCache, name string) probeString {
	if value, ok := cache.services[name]; ok {
		return value
	}
	if cache.remaining <= 0 {
		return probeString{reason: "probe_budget_exhausted"}
	}
	cache.remaining--
	value, ok, reason := e.probe.ServiceState(ctx, name)
	result := probeString{value: value, ok: ok, reason: reason}
	cache.services[name] = result
	return result
}

func (e *Evaluator) reboot(ctx context.Context, cache *probeCache) probeBool {
	if cache.reboot != nil {
		return *cache.reboot
	}
	if cache.remaining <= 0 {
		return probeBool{reason: "probe_budget_exhausted"}
	}
	cache.remaining--
	value, ok, reason := e.probe.RebootPending(ctx)
	result := probeBool{value: value, ok: ok, reason: reason}
	cache.reboot = &result
	return result
}

func classifyNumeric(value float64, threshold Threshold) string {
	breached := func(bound *float64) bool {
		if bound == nil {
			return false
		}
		switch threshold.Op {
		case "gt":
			return value > *bound
		case "gte":
			return value >= *bound
		case "lt":
			return value < *bound
		case "lte":
			return value <= *bound
		default:
			return false
		}
	}
	if breached(threshold.Critical) {
		return "critical"
	}
	if breached(threshold.Warning) {
		return "warning"
	}
	return "ok"
}

func applyHysteresis(raw string, state *CheckState, hysteresis Hysteresis) string {
	if hysteresis.RaiseSamples < 1 {
		hysteresis.RaiseSamples = 1
	}
	if hysteresis.ClearSamples < 1 {
		hysteresis.ClearSamples = 1
	}
	if raw == "unknown" {
		state.Status = raw
		state.PendingStatus = ""
		state.PendingCount = 0
		return raw
	}
	if state.Status == "" {
		required := 1
		if raw == "warning" || raw == "critical" {
			required = hysteresis.RaiseSamples
		}
		if required == 1 {
			state.Status = raw
			return raw
		}
		state.Status = "unknown"
		state.PendingStatus = raw
		state.PendingCount = 1
		return state.Status
	}
	if raw == state.Status {
		state.PendingStatus = ""
		state.PendingCount = 0
		return state.Status
	}
	severity := map[string]int{"unknown": -1, "ok": 0, "warning": 1, "critical": 2}
	required := hysteresis.ClearSamples
	if severity[raw] > severity[state.Status] {
		required = hysteresis.RaiseSamples
	}
	if state.Status == "unknown" && raw == "ok" {
		required = 1
	}
	if state.PendingStatus == raw {
		state.PendingCount++
	} else {
		state.PendingStatus = raw
		state.PendingCount = 1
	}
	if state.PendingCount >= required {
		state.Status = raw
		state.PendingStatus = ""
		state.PendingCount = 0
	}
	return state.Status
}

func resultID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate monitoring result ID: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
