//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

const installTimeout = 20 * time.Minute

const psInstallScript = `
$ErrorActionPreference = 'Stop'

$result = [ordered]@{
  status = 'success'
  installed_kbs = @()
  failed_kbs = @()
  results = @()
  reboot_required = $false
  message = ''
}

try {
  $si = New-Object -ComObject Microsoft.Update.SystemInfo
  $result.reboot_required = [bool]$si.RebootRequired
} catch { }

try {
  $session  = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $search   = $searcher.Search("IsInstalled=0 and IsHidden=0")
  
  if ($search.Updates.Count -eq 0) {
    if ($InstallAll) {
      $result.message = 'No missing updates found to install.'
    } else {
      # Explicit targets on a fully patched endpoint matched nothing; reporting
      # success would claim the requested KBs or Update IDs were handled.
      $result.status = 'failed'
      $result.message = 'None of the requested KB or Windows Update IDs were found among applicable missing updates.'
    }
    $result | ConvertTo-Json -Depth 3 -Compress
    exit 0
  }

  $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $search.Updates) {
    $match = $false
    if ($InstallAll) {
      $match = $true
    } else {
      $updateID = [string]$u.Identity.UpdateID
      if ($TargetUpdateIDs -contains $updateID) { $match = $true }
      foreach ($kb in $u.KBArticleIDs) {
        $formatted = 'KB' + $kb
        if ($TargetKBs -contains $formatted -or $TargetKBs -contains $kb.ToString()) {
          $match = $true
          break
        }
      }
    }
    if ($match) {
      $toInstall.Add($u) | Out-Null
    }
  }

  if ($toInstall.Count -eq 0) {
    $result.status = 'failed'
    $result.message = 'None of the requested KB or Windows Update IDs were found among applicable missing updates.'
    $result | ConvertTo-Json -Depth 3 -Compress
    exit 0
  }

  foreach ($u in $toInstall) {
    if (-not $u.EulaAccepted) { $u.AcceptEula() }
  }

  # Download phase. The download result is captured, never left on the pipeline:
  # an unassigned COM return value is formatted onto stdout ahead of the JSON.
  $downloader = $session.CreateUpdateDownloader()
  $downloader.Updates = $toInstall
  $null = $downloader.Download()

  # Install phase
  $installer = $session.CreateUpdateInstaller()
  $installer.Updates = $toInstall
  $installRes = $installer.Install()

  for ($i = 0; $i -lt $toInstall.Count; $i++) {
    $u = $toInstall.Item($i)
    $kbStr = ''
    if ($u.KBArticleIDs.Count -gt 0) { $kbStr = 'KB' + $u.KBArticleIDs.Item(0) } else { $kbStr = $u.Identity.UpdateID }
    
    $uResult = $installRes.GetUpdateResult($i)
    $hr = ('0x{0:X8}' -f ($uResult.HResult -band 0xFFFFFFFF))
    $uReboot = [bool]$uResult.RebootRequired
    $result.results += [ordered]@{ identifier = $kbStr; result_code = [int]$uResult.ResultCode; hresult = $hr; reboot_required = $uReboot }
    if ($uReboot) { $result.reboot_required = $true }
    if ($uResult.ResultCode -eq 2) { # 2 = OperationResultCode.orcSucceeded
      $result.installed_kbs += $kbStr
    } else {
      $result.failed_kbs += $kbStr
    }
  }

  if ($installRes.RebootRequired) {
    $result.reboot_required = $true
  }
  if ($result.failed_kbs.Count -gt 0 -and $result.installed_kbs.Count -gt 0) {
    $result.status = 'partial'
  } elseif ($result.failed_kbs.Count -gt 0 -and $result.installed_kbs.Count -eq 0) {
    $result.status = 'failed'
  }
  $result.message = "Installed $($result.installed_kbs.Count) update(s), $($result.failed_kbs.Count) failed."
} catch {
  $result.status = 'failed'
  $result.message = $_.Exception.Message
}

$result | ConvertTo-Json -Depth 3 -Compress
`

// Install downloads and installs the explicitly selected targets. Installing all
// applicable updates requires targets.All; an empty request is rejected.
func Install(ctx context.Context, targets InstallTargets) (InstallResult, error) {
	normalized, err := NormalizeInstallTargets(targets)
	if err != nil {
		return InstallResult{Status: "failed", Message: err.Error()}, err
	}

	// -EncodedCommand keeps the long multi-line script clear of command-line
	// quoting; the selection travels in the environment.
	run, err := runPS(ctx, pwsh.Script{
		Body:    psInstallPrefix + "\n" + psInstallScript,
		Env:     installEnv(normalized),
		Timeout: installTimeout,
		Encoded: true,
	})
	if err != nil && len(run.Stdout) == 0 {
		return InstallResult{
			Status:  "failed",
			Message: fmt.Sprintf("powershell install execution failed: %v: %s", err, run.Stderr),
		}, err
	}

	var res InstallResult
	if err := json.Unmarshal(extractPSJSON(run.Stdout), &res); err != nil {
		return InstallResult{
			Status:  "failed",
			Message: fmt.Sprintf("failed to parse install script result JSON: %v, raw stdout: %s", err, run.Stdout),
		}, err
	}

	return res, nil
}
