// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"testing"
)

func TestDecideReboot(t *testing.T) {
	cases := []struct {
		name string
		in   RebootDecisionInput
		want string
	}{
		{"unknown policy is skipped", RebootDecisionInput{Policy: "never"}, RebootSkipped},
		{"if_required with no pending reboot", RebootDecisionInput{Policy: "if_required", RebootRequired: false}, RebootNotNeeded},
		{"if_required with pending reboot, no user", RebootDecisionInput{Policy: "if_required", RebootRequired: true}, RebootScheduled},
		{"forced reboots even without pending", RebootDecisionInput{Policy: "forced", RebootRequired: false}, RebootScheduled},
		{"consent defers when a user is present", RebootDecisionInput{Policy: "forced", RequiresNoUser: true, RebootRequired: true, ActiveUser: `NODELINK\\u`}, RebootDeferred},
		{"forced through when consent not required", RebootDecisionInput{Policy: "forced", RequiresNoUser: false, ActiveUser: `NODELINK\\u`}, RebootScheduled},
	}
	for _, tc := range cases {
		if got := DecideReboot(tc.in); got != tc.want {
			t.Errorf("%s: DecideReboot() = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestInstallWithRetryRetriesFailedKBs(t *testing.T) {
	original := installOnce
	t.Cleanup(func() { installOnce = original })

	calls := 0
	installOnce = func(_ context.Context, targets InstallTargets) (InstallResult, error) {
		calls++
		if calls == 1 {
			// First pass: KB1 succeeds, KB2 fails.
			return InstallResult{
				Status:       "partial",
				InstalledKBs: []string{"KB5001111"},
				FailedKBs:    []string{"KB5002222"},
				Results: []UpdateOutcome{
					{Identifier: "KB5001111", ResultCode: 2},
					{Identifier: "KB5002222", ResultCode: 4, HResult: "0x80240022"},
				},
			}, nil
		}
		// Retry should target only the failed KB2, which now succeeds.
		if len(targets.KBIDs) != 1 || targets.KBIDs[0] != "KB5002222" {
			t.Fatalf("retry must target only the failed KB, got %v", targets.KBIDs)
		}
		return InstallResult{
			Status:       "success",
			InstalledKBs: []string{"KB5002222"},
			Results:      []UpdateOutcome{{Identifier: "KB5002222", ResultCode: 2}},
		}, nil
	}

	res, err := InstallWithRetry(context.Background(), InstallTargets{KBIDs: []string{"KB5001111", "KB5002222"}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "success" {
		t.Fatalf("expected success after retry, got %q", res.Status)
	}
	if len(res.FailedKBs) != 0 {
		t.Fatalf("expected no failures after retry, got %v", res.FailedKBs)
	}
	if calls != 2 {
		t.Fatalf("expected exactly 2 install attempts, got %d", calls)
	}
	var kb2 *UpdateOutcome
	for i := range res.Results {
		if res.Results[i].Identifier == "KB5002222" {
			kb2 = &res.Results[i]
		}
	}
	if kb2 == nil || kb2.Attempts != 2 || kb2.ResultCode != 2 {
		t.Fatalf("KB2 outcome not merged correctly: %+v", kb2)
	}
}

func TestInstallWithRetryStopsAtMaxAttempts(t *testing.T) {
	original := installOnce
	t.Cleanup(func() { installOnce = original })

	calls := 0
	installOnce = func(_ context.Context, _ InstallTargets) (InstallResult, error) {
		calls++
		return InstallResult{
			Status:    "failed",
			FailedKBs: []string{"KB5009999"},
			Results:   []UpdateOutcome{{Identifier: "KB5009999", ResultCode: 4}},
		}, nil
	}
	res, err := InstallWithRetry(context.Background(), InstallTargets{KBIDs: []string{"KB5009999"}}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 bounded attempts, got %d", calls)
	}
	if res.Status != "failed" || len(res.FailedKBs) != 1 {
		t.Fatalf("expected persistent failure, got %+v", res)
	}
}
