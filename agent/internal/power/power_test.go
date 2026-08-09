// SPDX-License-Identifier: AGPL-3.0-only
package power

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func withPlatformFakes(t *testing.T) (*bool, *bool) {
	t.Helper()
	originalSchedule, originalCancel, originalUser := scheduleAction, cancelAction, activeUser
	scheduled, cancelled := false, false
	scheduleAction = func(_ context.Context, _ string, _ int, _ string) (string, string, error) {
		scheduled = true
		return "scheduled", "accepted", nil
	}
	cancelAction = func(_ context.Context) (string, string, error) {
		cancelled = true
		return "none_pending", "nothing pending", nil
	}
	activeUser = func(_ context.Context) (string, error) { return "", nil }
	t.Cleanup(func() {
		scheduleAction, cancelAction, activeUser = originalSchedule, originalCancel, originalUser
	})
	return &scheduled, &cancelled
}

func scheduleJSON(now time.Time, updates map[string]any) json.RawMessage {
	payload := map[string]any{
		"confirm": true, "reason": "Approved maintenance reboot",
		"delay_seconds": 60, "user_consent": "confirmed",
		"maintenance_window_id":      "window-1",
		"maintenance_window_ends_at": now.Add(time.Hour).Format(time.RFC3339Nano),
		"user_present_at_dispatch":   true,
	}
	for key, value := range updates {
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func TestScheduleReturnsBoundedPolicyEvidence(t *testing.T) {
	scheduled, _ := withPlatformFakes(t)
	now := time.Now().UTC()
	result := executeAt(context.Background(), KindReboot, scheduleJSON(now, nil), now)
	if result.ExitCode != 0 || !*scheduled {
		t.Fatalf("result=%+v scheduled=%v", result, *scheduled)
	}
	if strings.Contains(result.Stdout, "Approved maintenance reboot") || !strings.Contains(result.Stdout, `"status":"scheduled"`) {
		t.Fatalf("result must contain structured evidence without raw reason: %s", result.Stdout)
	}
}

func TestScheduleRefusesNewUserWithoutConsent(t *testing.T) {
	scheduled, _ := withPlatformFakes(t)
	activeUser = func(_ context.Context) (string, error) { return `NODELINK\\user`, nil }
	now := time.Now().UTC()
	result := executeAt(context.Background(), KindShutdown, scheduleJSON(now, map[string]any{"user_consent": "no_user_session", "user_present_at_dispatch": false}), now)
	if result.ExitCode == 0 || *scheduled || !strings.Contains(result.Stderr, "interactive user") {
		t.Fatalf("result=%+v scheduled=%v", result, *scheduled)
	}
}

func TestScheduleRefusesActionPastWindow(t *testing.T) {
	scheduled, _ := withPlatformFakes(t)
	now := time.Now().UTC()
	result := executeAt(context.Background(), KindReboot, scheduleJSON(now, map[string]any{"maintenance_window_ends_at": now.Add(30 * time.Second).Format(time.RFC3339Nano)}), now)
	if result.ExitCode == 0 || *scheduled {
		t.Fatalf("result=%+v scheduled=%v", result, *scheduled)
	}
}

func TestCancelIsIdempotentWhenNothingPending(t *testing.T) {
	_, cancelled := withPlatformFakes(t)
	raw := json.RawMessage(`{"confirm":true,"reason":"Operator cancelled maintenance"}`)
	result := executeAt(context.Background(), KindCancelPowerAction, raw, time.Now().UTC())
	if result.ExitCode != 0 || !*cancelled || !strings.Contains(result.Stdout, "none_pending") {
		t.Fatalf("result=%+v cancelled=%v", result, *cancelled)
	}
}

func TestPayloadRejectsUnknownFields(t *testing.T) {
	scheduled, _ := withPlatformFakes(t)
	now := time.Now().UTC()
	result := executeAt(context.Background(), KindReboot, scheduleJSON(now, map[string]any{"script": "shutdown now"}), now)
	if result.ExitCode == 0 || *scheduled {
		t.Fatalf("result=%+v scheduled=%v", result, *scheduled)
	}
}

func TestPayloadRejectsControlCharactersInReason(t *testing.T) {
	scheduled, _ := withPlatformFakes(t)
	now := time.Now().UTC()
	result := executeAt(context.Background(), KindReboot, scheduleJSON(now, map[string]any{"reason": "approved maintenance\nrestart"}), now)
	if result.ExitCode == 0 || *scheduled {
		t.Fatalf("result=%+v scheduled=%v", result, *scheduled)
	}
}
