// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"strings"
)

// BitLocker volume state.
//
// The Select-Object list is the security boundary of this collector. It names
// exactly the properties we want, so KeyProtector — which carries recovery
// passwords — is never read, never serialized, and never reaches this process.
// An allowlist rather than a filter: there is no path by which a key could be
// collected and then dropped, because it is never fetched.
//
// Access-denied is reported distinctly from other failures. The cmdlets need
// elevation, and an agent lacking it should surface a fixable deployment
// problem rather than an indefinite generic failure.
const bitlockerScript = `
$supported = [bool](Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue)
$denied = $false
$volumes = @()
if ($supported) {
  try {
    $volumes = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
      [pscustomobject]@{
        mount_point           = [string]$_.MountPoint
        protection_status     = [string]$_.ProtectionStatus
        volume_status         = [string]$_.VolumeStatus
        encryption_method     = [string]$_.EncryptionMethod
        encryption_percentage = [int]$_.EncryptionPercentage
        is_system_volume      = [bool]($_.VolumeType -eq 'OperatingSystem')
      }
    })
  } catch [System.UnauthorizedAccessException] {
    $denied = $true
  } catch {
    if ($_.Exception.Message -match 'Access is denied|requires elevation') { $denied = $true }
  }
}
[pscustomobject]@{
  supported = $supported
  denied    = $denied
  available = (-not $denied)
  volumes   = $volumes
} | ConvertTo-Json -Compress -Depth 4`

// Secure Boot. Confirm-SecureBootUEFI throws on legacy BIOS firmware, which is
// "this machine cannot have Secure Boot", not "Secure Boot is off".
const secureBootScript = `
$uefi = $true
$denied = $false
$enabled = $null
try {
  $enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
} catch [System.PlatformNotSupportedException] {
  $uefi = $false
} catch {
  if ($_.Exception.Message -match 'not supported on this platform|Cmdlet not supported') { $uefi = $false }
  elseif ($_.Exception.Message -match 'Access is denied|requires elevation') { $denied = $true }
}
[pscustomobject]@{
  uefi      = $uefi
  denied    = $denied
  available = ($null -ne $enabled)
  enabled   = $enabled
} | ConvertTo-Json -Compress -Depth 3`

// TPM presence and readiness.
const tpmScript = `
$supported = [bool](Get-Command Get-Tpm -ErrorAction SilentlyContinue)
$denied = $false
$tpm = $null
if ($supported) {
  try { $tpm = Get-Tpm -ErrorAction Stop }
  catch {
    if ($_.Exception.Message -match 'Access is denied|requires elevation') { $denied = $true }
  }
}
$spec = $null
try {
  $spec = [string](Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm -ErrorAction Stop).SpecVersion
} catch { $spec = $null }
$mfr = $null
try {
  $mfr = [string](Get-CimInstance -Namespace root/cimv2/security/microsofttpm -ClassName Win32_Tpm -ErrorAction Stop).ManufacturerIdTxt
} catch { $mfr = $null }
[pscustomobject]@{
  supported    = $supported
  denied       = $denied
  available    = [bool]$tpm
  present      = if ($tpm) { [bool]$tpm.TpmPresent } else { $null }
  enabled      = if ($tpm) { [bool]$tpm.TpmEnabled } else { $null }
  activated    = if ($tpm) { [bool]$tpm.TpmActivated } else { $null }
  owned        = if ($tpm) { [bool]$tpm.TpmOwned } else { $null }
  spec_version = $spec
  manufacturer = $mfr
} | ConvertTo-Json -Compress -Depth 3`

// StatusPermissionDenied mirrors the server's InventorySectionStatus member.
// It is distinct from StatusUnavailable because the two call for different
// responses: unavailable is a fault to retry, denied means the agent is not
// running with the privileges its collectors need — a fixable deployment
// problem that would otherwise hide inside generic failures.
const StatusPermissionDenied = "permission_denied"

// BitLocker protection states, as the wire reports them.
const (
	ProtectionOn      = "on"
	ProtectionOff     = "off"
	ProtectionUnknown = "unknown"
)

// Firmware types.
const (
	FirmwareUEFI    = "uefi"
	FirmwareBIOS    = "bios"
	FirmwareUnknown = "unknown"
)

// RawBitLockerVolume is one volume as read from the endpoint.
//
// Note what is absent: there is no field for a recovery key or key-protector
// password, and the collector never queries one. Recovery keys are the single
// piece of data whose disclosure defeats the control outright, so the safest
// structure is one with nowhere to put them.
type RawBitLockerVolume struct {
	MountPoint       string `json:"mount_point"`
	ProtectionStatus string `json:"protection_status"`
	VolumeStatus     string `json:"volume_status"`
	EncryptionMethod string `json:"encryption_method"`
	Percentage       *int   `json:"encryption_percentage"`
	IsSystemVolume   *bool  `json:"is_system_volume"`
}

// RawBitLocker carries the reading plus how it went.
type RawBitLocker struct {
	Supported bool
	Denied    bool
	Available bool
	Volumes   []RawBitLockerVolume
}

// normalizeProtection maps BitLocker's reported protection status. Anything
// unrecognized becomes "unknown" rather than being assumed off — claiming a
// volume is unprotected when we could not tell is the dangerous direction of
// the error.
func normalizeProtection(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "1":
		return ProtectionOn
	case "off", "0":
		return ProtectionOff
	default:
		return ProtectionUnknown
	}
}

// NormalizeBitLocker builds the section payload and status.
func NormalizeBitLocker(raw RawBitLocker) (map[string]any, string) {
	switch {
	case !raw.Supported:
		return map[string]any{}, StatusUnsupported
	case raw.Denied:
		// The volumes exist; we simply are not allowed to look. Reporting an
		// empty volume list as "ok" would read as "nothing is encrypted".
		return map[string]any{}, StatusPermissionDenied
	case !raw.Available:
		return map[string]any{}, StatusUnavailable
	}

	status := StatusOK
	volumes := raw.Volumes
	if len(volumes) > MaxVolumes {
		volumes = volumes[:MaxVolumes]
		status = StatusPartial
	}

	out := make([]map[string]any, 0, len(volumes))
	for _, volume := range volumes {
		entry := map[string]any{
			"protection_status": normalizeProtection(volume.ProtectionStatus),
		}
		if mount := strings.TrimSpace(volume.MountPoint); mount != "" {
			entry["mount_point"] = mount
		}
		if state := strings.TrimSpace(volume.VolumeStatus); state != "" {
			entry["volume_status"] = state
		}
		if method := strings.TrimSpace(volume.EncryptionMethod); method != "" {
			entry["encryption_method"] = method
		}
		if volume.Percentage != nil && *volume.Percentage >= 0 && *volume.Percentage <= 100 {
			entry["encryption_percentage"] = *volume.Percentage
		}
		if volume.IsSystemVolume != nil {
			entry["is_system_volume"] = *volume.IsSystemVolume
		}
		out = append(out, entry)
	}
	return map[string]any{"volumes": out}, status
}

// RawSecureBoot is the Secure Boot reading.
type RawSecureBoot struct {
	// UEFI is false on legacy-BIOS firmware, where Secure Boot cannot exist.
	UEFI      bool
	Available bool
	Denied    bool
	Enabled   *bool
}

// NormalizeSecureBoot builds the section payload and status.
//
// A legacy-BIOS machine reports `unsupported`, not `enabled=false`. Secure
// Boot is a UEFI feature; describing a BIOS machine as having it "disabled"
// would flag a machine behaving correctly for its firmware — the same shape of
// false alarm as reading passive Defender as disabled.
func NormalizeSecureBoot(raw RawSecureBoot) (map[string]any, string) {
	if !raw.UEFI {
		return map[string]any{"firmware_type": FirmwareBIOS}, StatusUnsupported
	}
	if raw.Denied {
		return map[string]any{"firmware_type": FirmwareUEFI}, StatusPermissionDenied
	}
	if !raw.Available || raw.Enabled == nil {
		return map[string]any{"firmware_type": FirmwareUEFI}, StatusUnavailable
	}
	return map[string]any{
		"firmware_type": FirmwareUEFI,
		"enabled":       *raw.Enabled,
	}, StatusOK
}

// RawTpm is the TPM reading.
type RawTpm struct {
	Supported bool
	Available bool
	Denied    bool

	Present      *bool
	Enabled      *bool
	Activated    *bool
	Owned        *bool
	SpecVersion  string
	Manufacturer string
}

// NormalizeTpm builds the section payload and status.
//
// "No TPM present" is a real answer worth recording — it is why a machine
// cannot use a TPM-backed BitLocker protector — and is reported as a
// successful collection, not as a failure to read.
func NormalizeTpm(raw RawTpm) (map[string]any, string) {
	switch {
	case !raw.Supported:
		return map[string]any{}, StatusUnsupported
	case raw.Denied:
		return map[string]any{}, StatusPermissionDenied
	case !raw.Available:
		return map[string]any{}, StatusUnavailable
	}

	payload := map[string]any{}
	if raw.Present != nil {
		payload["present"] = *raw.Present
	}
	if raw.Enabled != nil {
		payload["enabled"] = *raw.Enabled
	}
	if raw.Activated != nil {
		payload["activated"] = *raw.Activated
	}
	if version := strings.TrimSpace(raw.SpecVersion); version != "" {
		payload["spec_version"] = version
	}
	if manufacturer := strings.TrimSpace(raw.Manufacturer); manufacturer != "" {
		payload["manufacturer"] = manufacturer
	}
	// Readiness is only asserted when every component is known and true.
	// Deriving it from partial information would overstate the machine's
	// posture, which is the direction of error that matters here.
	if raw.Present != nil && raw.Enabled != nil && raw.Activated != nil && raw.Owned != nil {
		payload["ready"] = *raw.Present && *raw.Enabled && *raw.Activated && *raw.Owned
	}
	return payload, StatusOK
}
