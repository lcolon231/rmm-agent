// SPDX-License-Identifier: AGPL-3.0-only
// Package power executes the typed, signed endpoint power-operation contract.
package power

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

const (
	KindReboot            = "reboot"
	KindShutdown          = "shutdown"
	KindCancelPowerAction = "cancel_power_action"
	minDelaySeconds       = 30
	maxDelaySeconds       = 3600
)

type schedulePayload struct {
	Confirm                 bool   `json:"confirm"`
	Reason                  string `json:"reason"`
	DelaySeconds            int    `json:"delay_seconds"`
	UserConsent             string `json:"user_consent"`
	MaintenanceWindowID     string `json:"maintenance_window_id"`
	MaintenanceWindowEndsAt string `json:"maintenance_window_ends_at"`
	UserPresentAtDispatch   bool   `json:"user_present_at_dispatch"`
}

type cancelPayload struct {
	Confirm bool   `json:"confirm"`
	Reason  string `json:"reason"`
}

type Result struct {
	Status                  string `json:"status"`
	Action                  string `json:"action"`
	DelaySeconds            int    `json:"delay_seconds,omitempty"`
	MaintenanceWindowID     string `json:"maintenance_window_id,omitempty"`
	MaintenanceWindowEndsAt string `json:"maintenance_window_ends_at,omitempty"`
	UserConsent             string `json:"user_consent,omitempty"`
	ReasonSHA256            string `json:"reason_sha256"`
	Message                 string `json:"message,omitempty"`
}

func decodeStrict(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

// Function seams keep platform calls mockable. This is especially important
// for Windows tests: a unit test must never schedule a real reboot.
var scheduleAction = platformSchedule
var cancelAction = platformCancel
var activeUser = platformActiveUser

func reasonDigest(reason string) string {
	sum := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(sum[:])
}

func validateReason(reason string) error {
	hasControl := strings.IndexFunc(reason, func(r rune) bool { return r < 32 || r == 127 }) >= 0
	if reason != strings.TrimSpace(reason) || len(reason) < 10 || len(reason) > 512 || hasControl {
		return fmt.Errorf("reason must contain 10-512 trimmed printable UTF-8 bytes")
	}
	return nil
}

func resultError(status, action, reason, stderr string) executor.Result {
	out, _ := json.Marshal(Result{
		Status: status, Action: action, ReasonSHA256: reasonDigest(reason), Message: stderr,
	})
	return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: stderr}
}

func executeAt(ctx context.Context, kind string, raw json.RawMessage, now time.Time) executor.Result {
	if kind == KindCancelPowerAction {
		var payload cancelPayload
		if err := decodeStrict(raw, &payload); err != nil || !payload.Confirm || validateReason(payload.Reason) != nil {
			return resultError("invalid", kind, payload.Reason, "power cancellation payload is invalid")
		}
		status, message, err := cancelAction(ctx)
		out, _ := json.Marshal(Result{Status: status, Action: kind, ReasonSHA256: reasonDigest(payload.Reason), Message: message})
		if err != nil {
			return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: err.Error()}
		}
		return executor.Result{ExitCode: 0, Stdout: string(out)}
	}

	if kind != KindReboot && kind != KindShutdown {
		return resultError("unsupported", kind, "", "unsupported power operation")
	}
	var payload schedulePayload
	if err := decodeStrict(raw, &payload); err != nil || !payload.Confirm || validateReason(payload.Reason) != nil {
		return resultError("invalid", kind, payload.Reason, "power operation payload is invalid")
	}
	if payload.DelaySeconds < minDelaySeconds || payload.DelaySeconds > maxDelaySeconds ||
		(payload.UserConsent != "confirmed" && payload.UserConsent != "no_user_session") ||
		payload.MaintenanceWindowID == "" {
		return resultError("invalid", kind, payload.Reason, "power operation policy evidence is invalid")
	}
	windowEnd, err := time.Parse(time.RFC3339Nano, payload.MaintenanceWindowEndsAt)
	if err != nil || now.Add(time.Duration(payload.DelaySeconds)*time.Second).After(windowEnd) {
		return resultError("refused", kind, payload.Reason, "power operation is outside its signed maintenance window")
	}
	if payload.UserConsent == "no_user_session" {
		user, userErr := activeUser(ctx)
		if userErr != nil {
			return resultError("unavailable", kind, payload.Reason, "power operation refused: active-user state is unavailable")
		}
		if strings.TrimSpace(user) != "" {
			return resultError("refused", kind, payload.Reason, "power operation refused: an interactive user is active")
		}
	}

	status, message, err := scheduleAction(ctx, kind, payload.DelaySeconds, payload.Reason)
	out, _ := json.Marshal(Result{
		Status: status, Action: kind, DelaySeconds: payload.DelaySeconds,
		MaintenanceWindowID:     payload.MaintenanceWindowID,
		MaintenanceWindowEndsAt: payload.MaintenanceWindowEndsAt,
		UserConsent:             payload.UserConsent, ReasonSHA256: reasonDigest(payload.Reason), Message: message,
	})
	if err != nil {
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: err.Error()}
	}
	return executor.Result{ExitCode: 0, Stdout: string(out)}
}

// Execute validates the complete signed policy again at the endpoint before
// invoking the platform. The caller has already durably journaled executing.
func Execute(ctx context.Context, kind string, raw json.RawMessage) executor.Result {
	return executeAt(ctx, kind, raw, time.Now().UTC())
}

// ScheduleReboot schedules an OS restart after delaySeconds, reusing the same
// platform mechanism as a power operation. Exposed for the post-install reboot
// policy (issue #53); it goes through the same test seam as Execute.
func ScheduleReboot(ctx context.Context, delaySeconds int, reason string) (string, string, error) {
	return scheduleAction(ctx, KindReboot, delaySeconds, reason)
}

// ActiveUser returns the current interactive user, or an empty string when none
// is signed in. Reused by the post-install reboot consent check (issue #53).
func ActiveUser(ctx context.Context) (string, error) {
	return activeUser(ctx)
}
