// SPDX-License-Identifier: AGPL-3.0-only

package patching

// InstallResult captures the outcome of an on-demand update installation request.
type InstallResult struct {
	Status         string   `json:"status"`
	InstalledKBs   []string `json:"installed_kbs"`
	FailedKBs      []string `json:"failed_kbs"`
	RebootRequired bool     `json:"reboot_required"`
	Message        string   `json:"message"`
}
