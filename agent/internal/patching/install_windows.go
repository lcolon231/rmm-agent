//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"
)

const installTimeout = 20 * time.Minute

func encodeUTF16LE(s string) string {
	runes := []rune(s)
	encoded := utf16.Encode(runes)
	buf := make([]byte, len(encoded)*2)
	for i, u := range encoded {
		buf[i*2] = byte(u)
		buf[i*2+1] = byte(u >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}

const psInstallScript = `
$ErrorActionPreference = 'Stop'

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

// Install downloads and installs the explicitly selected targets. Installing all
// applicable updates requires targets.All; an empty request is rejected.
func Install(ctx context.Context, targets InstallTargets) (InstallResult, error) {
	ctx, cancel := context.WithTimeout(ctx, installTimeout)
	defer cancel()

	normalized, err := NormalizeInstallTargets(targets)
	if err != nil {
		return InstallResult{Status: "failed", Message: err.Error()}, err
	}

	arrayLiteral := func(values []string) string {
		if len(values) == 0 {
			return "@()"
		}
		quoted := make([]string, len(values))
		for i, value := range values {
			quoted[i] = fmt.Sprintf("'%s'", value)
		}
		return "@(" + strings.Join(quoted, ",") + ")"
	}
	prefix := fmt.Sprintf(
		"$InstallAll = $%t; $TargetKBs = %s; $TargetUpdateIDs = %s;",
		normalized.All,
		arrayLiteral(normalized.KBIDs),
		arrayLiteral(normalized.UpdateIDs),
	)

	fullScript := fmt.Sprintf("%s\n%s", prefix, psInstallScript)
	encoded := encodeUTF16LE(fullScript)

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded)
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
