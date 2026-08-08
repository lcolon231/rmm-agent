// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"fmt"
	"regexp"
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

// InstallResult captures the outcome of an on-demand update installation request.
type InstallResult struct {
	Status         string   `json:"status"`
	InstalledKBs   []string `json:"installed_kbs"`
	FailedKBs      []string `json:"failed_kbs"`
	RebootRequired bool     `json:"reboot_required"`
	Message        string   `json:"message"`
}
