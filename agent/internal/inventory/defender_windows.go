//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"time"
)

// Defender status plus the Security Center antivirus registry.
//
// Get-MpComputerStatus is the supported surface and is read-only — nothing
// here changes configuration, which the issue puts explicitly out of scope.
// Its absence is meaningful rather than an error: Server SKUs without the
// Defender feature have no cmdlet, which is "unsupported", not "failed".
//
// root/SecurityCenter2 lists registered antivirus products and does not exist
// on Server SKUs. That absence is reported separately so a machine with no
// Security Center is not mistaken for a machine with no antivirus.
const defenderScript = `
$supported = [bool](Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue)
$status = if ($supported) { Get-MpComputerStatus -ErrorAction SilentlyContinue } else { $null }
$scProducts = @()
$scQueryable = $false
try {
  $scProducts = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop |
    Where-Object { $_.displayName -and $_.displayName -notmatch 'Windows Defender|Microsoft Defender' } |
    ForEach-Object { [string]$_.displayName })
  $scQueryable = $true
} catch { $scQueryable = $false }
$iso = { param($v) if ($v) { ([datetime]$v).ToUniversalTime().ToString('o') } else { $null } }
[pscustomobject]@{
  supported        = $supported
  available        = [bool]$status
  running_mode     = if ($status) { [string]$status.AMRunningMode } else { $null }
  antivirus        = if ($status) { [bool]$status.AntivirusEnabled } else { $null }
  realtime         = if ($status) { [bool]$status.RealTimeProtectionEnabled } else { $null }
  tamper           = if ($status) { [bool]$status.IsTamperProtected } else { $null }
  signature        = if ($status) { [string]$status.AntivirusSignatureVersion } else { $null }
  signature_update = if ($status) { & $iso $status.AntivirusSignatureLastUpdated } else { $null }
  engine           = if ($status) { [string]$status.AMEngineVersion } else { $null }
  product          = if ($status) { [string]$status.AMProductVersion } else { $null }
  quick_scan       = if ($status) { & $iso $status.QuickScanEndTime } else { $null }
  full_scan        = if ($status) { & $iso $status.FullScanEndTime } else { $null }
  third_party      = $scProducts
  sc_queryable     = $scQueryable
} | ConvertTo-Json -Compress -Depth 4`

// collectDefender reads Defender status and hands it to the interpreter. Only
// the read lives here; every judgement about what the reading means is in
// defender.go and is tested on any platform.
func collectDefender(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, defenderScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}

	text := func(key string) string {
		value, _ := row[key].(string)
		return value
	}
	boolPtr := func(key string) *bool {
		value, ok := row[key].(bool)
		if !ok {
			return nil
		}
		return &value
	}
	flag := func(key string) bool {
		value, _ := row[key].(bool)
		return value
	}

	products := []string{}
	if raw, ok := row["third_party"].([]any); ok {
		for _, entry := range raw {
			if name, ok := entry.(string); ok {
				products = append(products, name)
			}
		}
	} else if name, ok := row["third_party"].(string); ok && name != "" {
		// PowerShell collapses a single-element array to a bare string.
		products = append(products, name)
	}

	return NormalizeDefender(RawDefender{
		Supported:               flag("supported"),
		Available:               flag("available"),
		RunningMode:             text("running_mode"),
		AntivirusEnabled:        boolPtr("antivirus"),
		RealtimeEnabled:         boolPtr("realtime"),
		TamperProtected:         boolPtr("tamper"),
		SignatureVersion:        text("signature"),
		SignatureLastUpdated:    text("signature_update"),
		EngineVersion:           text("engine"),
		ProductVersion:          text("product"),
		QuickScanEndTime:        text("quick_scan"),
		FullScanEndTime:         text("full_scan"),
		ThirdPartyProductNames:  products,
		SecurityCenterQueryable: flag("sc_queryable"),
	}, time.Now().UTC())
}
