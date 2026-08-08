//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"

	"github.com/lcolon231/rmm/agent/internal/inventory"
)

// scanTimeout bounds the whole Windows Update search. A live scan against the
// update service can take minutes, far longer than the heartbeat's per-section
// budget, which is exactly why this runs on the command path instead.
const scanTimeout = 10 * time.Minute

// rawScan is the shape the PowerShell collector emits: already-flattened rows so
// the pure normalizer in scan.go does the bounding and allowlisting.
type rawScan struct {
	RebootRequired *bool            `json:"reboot_required"`
	ErrorCode      string           `json:"error_code"`
	Missing        []map[string]any `json:"missing"`
	Installed      []map[string]any `json:"installed"`
}

// psScript shapes both missing (Windows Update Agent COM) and installed
// (Get-HotFix) updates into flat objects with exactly the keys scan.go expects.
// A search failure (for example an offline update service) is caught and
// reported as error_code with an empty missing list rather than failing the
// whole command, so the operator still learns the installed state and the error.
const psScript = `
$ErrorActionPreference = 'Stop'
$result = [ordered]@{ reboot_required = $null; error_code = ''; missing = @(); installed = @() }

try {
  $si = New-Object -ComObject Microsoft.Update.SystemInfo
  $result.reboot_required = [bool]$si.RebootRequired
} catch { }

try {
  $session  = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $search   = $searcher.Search("IsInstalled=0 and IsHidden=0")
  $missing  = @()
  foreach ($u in $search.Updates) {
    $kb = $null
    if ($u.KBArticleIDs.Count -gt 0) { $kb = 'KB' + $u.KBArticleIDs.Item(0) }
    $classification = $null; $product = $null
    foreach ($c in $u.Categories) {
      if ($c.Type -eq 'UpdateClassification' -and -not $classification) { $classification = $c.Name }
      if ($c.Type -eq 'Product' -and -not $product) { $product = $c.Name }
    }
    $url = $null
    if ($u.MoreInfoUrls.Count -gt 0) { $url = $u.MoreInfoUrls.Item(0) }
    $ldc = $null
    try { if ($u.LastDeploymentChangeTime) { $ldc = ([datetime]$u.LastDeploymentChangeTime).ToUniversalTime().ToString('o') } } catch { }
    $missing += [ordered]@{
      title                  = [string]$u.Title
      kb_id                  = $kb
      update_id              = [string]$u.Identity.UpdateID
      classification         = $classification
      product                = $product
      severity               = [string]$u.MsrcSeverity
      reboot_required        = ($u.InstallationBehavior.RebootBehavior -ne 0)
      is_downloaded          = [bool]$u.IsDownloaded
      support_url            = $url
      last_deployment_change = $ldc
    }
  }
  $result.missing = $missing
} catch {
  $result.error_code = $_.Exception.HResult.ToString()
}

try {
  $installed = @()
  foreach ($h in Get-HotFix) {
    $on = $null
    try { if ($h.InstalledOn) { $on = ([datetime]$h.InstalledOn).ToUniversalTime().ToString('o') } } catch { }
    $installed += [ordered]@{
      kb_id        = [string]$h.HotFixID
      title        = [string]$h.Description
      installed_on = $on
      installed_by = [string]$h.InstalledBy
    }
  }
  $result.installed = $installed
} catch { }

$result | ConvertTo-Json -Depth 4 -Compress
`

// Scan runs the on-demand Windows Update scan and returns the normalized section
// plus a bounded summary. A collector failure is returned as an error; a search
// failure that still yields installed state is returned as a section with a
// non-empty error_code and StatusUnavailable.
func Scan(ctx context.Context) (inventory.Section, Summary, error) {
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", psScript)
	out, err := cmd.Output()
	if err != nil {
		return inventory.Section{}, Summary{}, err
	}

	var raw rawScan
	if err := json.Unmarshal(out, &raw); err != nil {
		return inventory.Section{}, Summary{}, err
	}
	section, summary := BuildSection(
		raw.Missing, raw.Installed, time.Now().UTC(), raw.RebootRequired, raw.ErrorCode,
	)
	return section, summary, nil
}
