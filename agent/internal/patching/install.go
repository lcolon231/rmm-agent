// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const MaxInstallTargets = 100

var (
	kbTargetPattern       = regexp.MustCompile(`(?i)^KB[0-9]{4,10}$`)
	updateIDTargetPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// InstallTargets is the fail-closed selection for one installation command.
// All must be explicitly true when no identifiers are supplied.
type InstallTargets struct {
	All       bool
	KBIDs     []string
	UpdateIDs []string
}

// NormalizeInstallTargets validates, normalizes, and deduplicates signed target
// values before they are embedded into the PowerShell command.
func NormalizeInstallTargets(targets InstallTargets) (InstallTargets, error) {
	if targets.All && (len(targets.KBIDs) > 0 || len(targets.UpdateIDs) > 0) {
		return InstallTargets{}, fmt.Errorf("install_all cannot be combined with update identifiers")
	}
	if len(targets.KBIDs)+len(targets.UpdateIDs) > MaxInstallTargets {
		return InstallTargets{}, fmt.Errorf("at most %d update targets are allowed", MaxInstallTargets)
	}

	normalized := InstallTargets{All: targets.All}
	seenKBs := map[string]bool{}
	for _, value := range targets.KBIDs {
		kb := strings.ToUpper(strings.TrimSpace(value))
		if kb != "" && !strings.HasPrefix(kb, "KB") {
			kb = "KB" + kb
		}
		if !kbTargetPattern.MatchString(kb) {
			return InstallTargets{}, fmt.Errorf("invalid KB target %q", value)
		}
		if !seenKBs[kb] {
			seenKBs[kb] = true
			normalized.KBIDs = append(normalized.KBIDs, kb)
		}
	}

	seenUpdateIDs := map[string]bool{}
	for _, value := range targets.UpdateIDs {
		updateID := strings.ToLower(strings.TrimSpace(value))
		if !updateIDTargetPattern.MatchString(updateID) {
			return InstallTargets{}, fmt.Errorf("invalid Windows Update ID %q", value)
		}
		if !seenUpdateIDs[updateID] {
			seenUpdateIDs[updateID] = true
			normalized.UpdateIDs = append(normalized.UpdateIDs, updateID)
		}
	}

	if !normalized.All && len(normalized.KBIDs) == 0 && len(normalized.UpdateIDs) == 0 {
		return InstallTargets{}, fmt.Errorf("choose at least one KB or Update ID, or explicitly request install_all")
	}
	return normalized, nil
}

// UpdateOutcome is the per-update result of an install attempt (issue #53).
type UpdateOutcome struct {
	Identifier string `json:"identifier"`
	ResultCode int    `json:"result_code"`
	HResult    string `json:"hresult,omitempty"`
	Attempts   int    `json:"attempts"`
}

// RebootOutcome records the post-install reboot decision (issue #53).
type RebootOutcome struct {
	Policy       string `json:"policy"`
	Decision     string `json:"decision"`
	DelaySeconds int    `json:"delay_seconds,omitempty"`
}

// InstallResult captures the outcome of an on-demand update installation request.
type InstallResult struct {
	Status         string          `json:"status"`
	InstalledKBs   []string        `json:"installed_kbs"`
	FailedKBs      []string        `json:"failed_kbs"`
	Results        []UpdateOutcome `json:"results,omitempty"`
	RebootRequired bool            `json:"reboot_required"`
	Reboot         *RebootOutcome  `json:"reboot,omitempty"`
	Message        string          `json:"message"`
}

// installOnce is a seam over the platform install so retry orchestration and
// tests do not shell out to the real Windows Update service.
var installOnce = Install

// InstallWithRetry installs the targets and retries KB-identified failures up to
// maxAttempts (issue #53). WUA installs are idempotent per update, so a retry
// never double-installs a succeeded update; only failures are re-attempted, by
// KB. Per-update outcomes carry the number of attempts made.
func InstallWithRetry(ctx context.Context, targets InstallTargets, maxAttempts int) (InstallResult, error) {
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	first, err := installOnce(ctx, targets)
	if err != nil {
		return first, err
	}
	if len(first.Results) == 0 {
		return first, nil // platform reported no per-update detail (e.g. unsupported)
	}

	outcomes := map[string]UpdateOutcome{}
	order := []string{}
	for _, outcome := range first.Results {
		outcome.Attempts = 1
		if _, seen := outcomes[outcome.Identifier]; !seen {
			order = append(order, outcome.Identifier)
		}
		outcomes[outcome.Identifier] = outcome
	}
	rebootRequired := first.RebootRequired
	message := first.Message

	for attempt := 2; attempt <= maxAttempts; attempt++ {
		retryable := retryableKBs(outcomes)
		if len(retryable) == 0 {
			break
		}
		retry, retryErr := installOnce(ctx, InstallTargets{KBIDs: retryable})
		if retryErr != nil {
			break
		}
		rebootRequired = rebootRequired || retry.RebootRequired
		if retry.Message != "" {
			message = retry.Message
		}
		for _, outcome := range retry.Results {
			prev, ok := outcomes[outcome.Identifier]
			if ok {
				outcome.Attempts = prev.Attempts + 1
			} else {
				outcome.Attempts = attempt
				order = append(order, outcome.Identifier)
			}
			outcomes[outcome.Identifier] = outcome
		}
	}
	return assembleInstallResult(outcomes, order, rebootRequired, message), nil
}

// retryableKBs returns the KB-identified updates that have not yet succeeded.
// Update-ID-only failures are not retried (they cannot be targeted by KB).
func retryableKBs(outcomes map[string]UpdateOutcome) []string {
	var kbs []string
	for identifier, outcome := range outcomes {
		if outcome.ResultCode != 2 && kbTargetPattern.MatchString(identifier) {
			kbs = append(kbs, identifier)
		}
	}
	sort.Strings(kbs)
	return kbs
}

func assembleInstallResult(
	outcomes map[string]UpdateOutcome, order []string, rebootRequired bool, message string,
) InstallResult {
	res := InstallResult{RebootRequired: rebootRequired, Message: message}
	for _, identifier := range order {
		outcome := outcomes[identifier]
		res.Results = append(res.Results, outcome)
		if outcome.ResultCode == 2 {
			res.InstalledKBs = append(res.InstalledKBs, identifier)
		} else {
			res.FailedKBs = append(res.FailedKBs, identifier)
		}
	}
	switch {
	case len(res.FailedKBs) == 0:
		res.Status = "success"
	case len(res.InstalledKBs) == 0:
		res.Status = "failed"
	default:
		res.Status = "partial"
	}
	return res
}
