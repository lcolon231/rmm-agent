// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/patching"
)

func fakePatchSeams(t *testing.T, result patching.InstallResult, activeUser string) *bool {
	origInstall, origUser, origReboot := patchInstallWithRetry, patchActiveUser, patchScheduleReboot
	t.Cleanup(func() {
		patchInstallWithRetry, patchActiveUser, patchScheduleReboot = origInstall, origUser, origReboot
	})
	scheduled := false
	patchInstallWithRetry = func(_ context.Context, _ patching.InstallTargets, _ int) (patching.InstallResult, error) {
		return result, nil
	}
	patchActiveUser = func(_ context.Context) (string, error) { return activeUser, nil }
	patchScheduleReboot = func(_ context.Context, _ int, _ string) (string, string, error) {
		scheduled = true
		return "scheduled", "", nil
	}
	return &scheduled
}

func TestRunUpdateInstallSchedulesRebootWhenNoUser(t *testing.T) {
	scheduled := fakePatchSeams(t, patching.InstallResult{
		Status: "success", InstalledKBs: []string{"KB1"}, RebootRequired: true,
	}, "")

	payload := json.RawMessage(`{"kb_ids":["KB1"],"max_attempts":2,"reboot":{"policy":"if_required","delay_seconds":300,"requires_no_user":true}}`)
	res := (&Agent{}).runUpdateInstall(context.Background(), payload)

	if !*scheduled {
		t.Fatal("expected a reboot to be scheduled when no user is present")
	}
	var out patching.InstallResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Reboot == nil || out.Reboot.Decision != patching.RebootScheduled {
		t.Fatalf("unexpected reboot outcome: %+v", out.Reboot)
	}
}

func TestRunUpdateInstallDefersRebootWhenUserPresent(t *testing.T) {
	scheduled := fakePatchSeams(t, patching.InstallResult{
		Status: "success", InstalledKBs: []string{"KB1"}, RebootRequired: true,
	}, `NODELINK\u`)

	payload := json.RawMessage(`{"kb_ids":["KB1"],"reboot":{"policy":"forced","delay_seconds":300,"requires_no_user":true}}`)
	res := (&Agent{}).runUpdateInstall(context.Background(), payload)

	if *scheduled {
		t.Fatal("must not schedule a reboot while a user is present and consent is required")
	}
	var out patching.InstallResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Reboot == nil || out.Reboot.Decision != patching.RebootDeferred {
		t.Fatalf("expected deferred reboot, got %+v", out.Reboot)
	}
}

func TestRunUpdateInstallNoRebootKeyLeavesResultUntouched(t *testing.T) {
	scheduled := fakePatchSeams(t, patching.InstallResult{
		Status: "success", InstalledKBs: []string{"KB1"}, RebootRequired: true,
	}, "")

	// No reboot policy in the payload (older/opted-out): install only, never reboot.
	res := (&Agent{}).runUpdateInstall(context.Background(), json.RawMessage(`{"kb_ids":["KB1"]}`))
	if *scheduled {
		t.Fatal("no reboot policy must never schedule a reboot")
	}
	var out patching.InstallResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	if out.Reboot != nil {
		t.Fatalf("expected no reboot outcome, got %+v", out.Reboot)
	}
}
