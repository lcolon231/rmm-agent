//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"encoding/json"
	"os/exec"
	"time"
)

// Per-section timeout. Inventory runs on the heartbeat goroutine, so a wedged
// CIM provider must not be able to stall check-in; the section it belongs to
// is reported unavailable and the rest still collect.
const sectionTimeout = 30 * time.Second

// collect gathers each section independently. A section that fails is returned
// with StatusUnavailable rather than dropped, so the server can distinguish
// "this machine reported no disks" from "we could not read the disks".
func collect(ctx context.Context) []Section {
	sections := make([]Section, 0, len(AllSections))
	collectors := map[string]func(context.Context) (map[string]any, string){
		SectionSystem:              collectSystem,
		SectionCPU:                 collectCPU,
		SectionMemory:              collectMemory,
		SectionStorage:             collectStorage,
		SectionNetwork:             collectNetwork,
		SectionInstalledSoftware:   collectSoftware,
		SectionSecurityDefender:    collectDefender,
		SectionSecurityBitLocker:   collectBitLocker,
		SectionSecuritySecureBoot:  collectSecureBoot,
		SectionSecurityTpm:         collectTpm,
		SectionLocalAdministrators: collectLocalAdministrators,
	}
	for _, name := range AllSections {
		payload, status := collectors[name](ctx)
		if payload == nil {
			payload = map[string]any{}
		}
		sections = append(sections, Section{
			Section:     name,
			Status:      status,
			CollectedAt: time.Now().UTC(),
			Payload:     payload,
		})
	}
	return sections
}

// psJSON runs a PowerShell snippet and decodes its JSON output into rows.
//
// Windows PowerShell 5.1 collapses a single-element array to a bare object, so
// the result is decoded as an array first and retried as one object. Getting
// this wrong would silently report a one-disk machine as having no disks.
func psJSON(ctx context.Context, script string) ([]map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, sectionTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}

	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err == nil {
		return rows, nil
	}
	var single map[string]any
	if err := json.Unmarshal(out, &single); err != nil {
		return nil, err
	}
	return []map[string]any{single}, nil
}

func collectSystem(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, `
$cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
$enc = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue
[pscustomobject]@{
  Manufacturer = $cs.Manufacturer
  Model = $cs.Model
  Serial = $bios.SerialNumber
  Chassis = if ($enc.ChassisTypes) { [string]$enc.ChassisTypes[0] } else { $null }
  BiosVendor = $bios.Manufacturer
  BiosVersion = $bios.SMBIOSBIOSVersion
  BiosReleaseDate = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToUniversalTime().ToString('o') } else { $null }
} | ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}
	return NormalizeSystem(rows)
}

func collectCPU(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, `
Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
  Select-Object -First 1 Name, Architecture, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed |
  ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}
	return NormalizeCPU(rows)
}

func collectMemory(ctx context.Context) (map[string]any, string) {
	totals, err := psJSON(ctx, `
Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue |
  Select-Object @{n='TotalPhysicalMemory';e={[string]$_.TotalPhysicalMemory}} |
  ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}
	moduleRows, err := psJSON(ctx, `
Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue |
  Select-Object @{n='Capacity';e={[string]$_.Capacity}}, Speed, DeviceLocator, Manufacturer, PartNumber |
  ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}

	return NormalizeMemory(totals, moduleRows)
}

func collectStorage(ctx context.Context) (map[string]any, string) {
	diskRows, err := psJSON(ctx, `
Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue |
  Select-Object Model, SerialNumber, @{n='Size';e={[string]$_.Size}}, MediaType, InterfaceType |
  ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}
	volumeRows, err := psJSON(ctx, `
Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue |
  Select-Object DeviceID, VolumeName, FileSystem, @{n='Size';e={[string]$_.Size}}, @{n='FreeSpace';e={[string]$_.FreeSpace}} |
  ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}

	return NormalizeStorage(diskRows, volumeRows)
}

func collectNetwork(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, `
$configs = @{}
Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
  ForEach-Object { $configs[[string]$_.Index] = $_ }
Get-CimInstance Win32_NetworkAdapter -Filter "PhysicalAdapter=True" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $cfg = $configs[[string]$_.Index]
    [pscustomobject]@{
      Name = $_.NetConnectionID
      Mac = $_.MACAddress
      AdapterType = $_.AdapterType
      Speed = if ($_.Speed) { [string]$_.Speed } else { $null }
      Dhcp = if ($cfg) { [bool]$cfg.DHCPEnabled } else { $null }
      Addresses = if ($cfg -and $cfg.IPAddress) { @($cfg.IPAddress) } else { @() }
    }
  } | ConvertTo-Json -Compress -Depth 4`)
	if err != nil {
		return nil, StatusUnavailable
	}

	return NormalizeNetwork(rows)
}
