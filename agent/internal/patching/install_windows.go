//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const installTimeout = 20 * time.Minute

// InstallResult captures the outcome of an on-demand update installation request.
type InstallResult struct {
	Status         string   `json:"status"`
	InstalledKBs   []string `json:"installed_kbs"`
	FailedKBs      []string `json:"failed_kbs"`
	RebootRequired bool     `json:"reboot_required"`
	Message        string   `json:"message"`
}

const psInstallScript = `
$ErrorActionPreference = 'Stop'
param([string[]]$TargetKBs)

$result = [ordered]@{
  status = 'success'
  installed_kbs = @()
  failed_kbs = @()
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
    $result.message = 'No missing updates found to install.'
    $result | ConvertTo-Json -Depth 3 -Compress
    exit 0
  }

  $toInstall = New-Object -ComObject Microsoft.Update.UpdateColl
  foreach ($u in $search.Updates) {
    $match = $false
    if (-not $TargetKBs -or $TargetKBs.Count -eq 0) {
      $match = $true
    } else {
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
    $result.message = 'None of the requested KB IDs were found among applicable missing updates.'
    $result | ConvertTo-Json -Depth 3 -Compress
    exit 0
  }

  # Download phase
  $downloader = $session.CreateUpdateDownloader()
  $downloader.Updates = $toInstall
  $downloader.Download()

  # Install phase
  $installer = $session.CreateUpdateInstaller()
  $installer.Updates = $toInstall
  $installRes = $installer.Install()

  for ($i = 0; $i -lt $toInstall.Count; $i++) {
    $u = $toInstall.Item($i)
    $kbStr = ''
    if ($u.KBArticleIDs.Count -gt 0) { $kbStr = 'KB' + $u.KBArticleIDs.Item(0) } else { $kbStr = $u.Identity.UpdateID }
    
    $uResult = $installRes.GetUpdateResult($i)
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

// Install downloads and installs specified target KBs (or all missing updates if targetKBs is empty).
func Install(ctx context.Context, targetKBs []string) (InstallResult, error) {
	ctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()

	formattedKBs := make([]string, 0, len(targetKBs))
	for _, kb := range targetKBs {
		trimmed := strings.TrimSpace(kb)
		if trimmed != "" {
			if !strings.HasPrefix(strings.ToUpper(trimmed), "KB") && !strings.Contains(trimmed, "-") {
				trimmed = "KB" + trimmed
			}
			formattedKBs = append(formattedKBs, trimmed)
		}
	}

	kbArg := ""
	if len(formattedKBs) > 0 {
		quoted := make([]string, len(formattedKBs))
		for i, k := range formattedKBs {
			quoted[i] = fmt.Sprintf("'%s'", k)
		}
		kbArg = "-TargetKBs " + strings.Join(quoted, ",")
	}

	cmdStr := fmt.Sprintf("%s\n& { %s } %s", "$ErrorActionPreference = 'Stop'", psInstallScript, kbArg)
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", cmdStr)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil && stdout.Len() == 0 {
		return InstallResult{
			Status:  "failed",
			Message: fmt.Sprintf("powershell install execution failed: %v: %s", err, stderr.String()),
		}, err
	}

	var res InstallResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return InstallResult{
			Status:  "failed",
			Message: fmt.Sprintf("failed to parse install script result JSON: %v, raw stdout: %s", err, stdout.String()),
		}, err
	}

	return res, nil
}
