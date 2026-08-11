// SPDX-License-Identifier: AGPL-3.0-only

package patching

import "strings"

// RebootDecisionInput is the signed policy plus live endpoint state used to
// decide a post-install reboot (issue #53).
type RebootDecisionInput struct {
	Policy         string // "if_required" | "forced"
	RequiresNoUser bool
	RebootRequired bool
	ActiveUser     string
}

// Reboot decisions.
const (
	RebootScheduled = "scheduled"
	RebootDeferred  = "deferred_user_present"
	RebootNotNeeded = "not_required"
	RebootSkipped   = "skipped"
)

// DecideReboot resolves the post-install reboot decision. Consent wins first: if
// the policy requires no user and one is present, the reboot is deferred
// regardless of policy — a forced reboot never yanks the machine from under a
// signed-in user unless the policy explicitly sets requires_no_user=false. An
// if_required policy is a no-op when the install did not request a reboot; a
// forced policy always reboots once consent is satisfied.
func DecideReboot(in RebootDecisionInput) string {
	if in.Policy != "if_required" && in.Policy != "forced" {
		return RebootSkipped
	}
	if in.RequiresNoUser && strings.TrimSpace(in.ActiveUser) != "" {
		return RebootDeferred
	}
	if in.Policy == "if_required" && !in.RebootRequired {
		return RebootNotNeeded
	}
	return RebootScheduled
}
