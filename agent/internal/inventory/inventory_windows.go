//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
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

// Absent values are omitted, never defaulted. An empty string or a zero would
// claim the endpoint reported something it did not.
func putStr(target map[string]any, key string, value any) {
	text, ok := value.(string)
	if !ok || text == "" {
		return
	}
	target[key] = text
}

func putNum(target map[string]any, key string, value any) {
	switch typed := value.(type) {
	case float64:
		target[key] = int64(typed)
	case string:
		// Disk and memory sizes are UInt64 and are stringified in the queries
		// above rather than risking a lossy float round-trip through JSON.
		if parsed, err := strconv.ParseInt(typed, 10, 64); err == nil {
			target[key] = parsed
		}
	}
}

func putBool(target map[string]any, key string, value any) {
	if flag, ok := value.(bool); ok {
		target[key] = flag
	}
}

func first(rows []map[string]any) map[string]any {
	if len(rows) == 0 {
		return nil
	}
	return rows[0]
}

// boundedStatus reports whether a collected list had to be trimmed.
func boundedStatus(collected, limit int) string {
	if collected > limit {
		return StatusPartial
	}
	return StatusOK
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
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	payload := map[string]any{}
	putStr(payload, "manufacturer", row["Manufacturer"])
	putStr(payload, "model", row["Model"])
	putStr(payload, "serial", row["Serial"])
	putStr(payload, "chassis", row["Chassis"])
	putStr(payload, "bios_vendor", row["BiosVendor"])
	putStr(payload, "bios_version", row["BiosVersion"])
	putStr(payload, "bios_release_date", row["BiosReleaseDate"])
	if len(payload) == 0 {
		return payload, StatusUnavailable
	}
	return payload, StatusOK
}

func collectCPU(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, `
Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue |
  Select-Object -First 1 Name, Architecture, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed |
  ConvertTo-Json -Compress -Depth 3`)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	payload := map[string]any{}
	putStr(payload, "name", row["Name"])
	putNum(payload, "physical_cores", row["NumberOfCores"])
	putNum(payload, "logical_cores", row["NumberOfLogicalProcessors"])
	putNum(payload, "max_clock_mhz", row["MaxClockSpeed"])
	if arch, ok := row["Architecture"].(float64); ok {
		payload["architecture"] = cpuArchitecture(int(arch))
	}
	if len(payload) == 0 {
		return payload, StatusUnavailable
	}
	return payload, StatusOK
}

// cpuArchitecture maps Win32_Processor.Architecture to a stable name. The raw
// integer is a Windows implementation detail; a technician reading inventory
// wants the name, and #36 onward compare these across endpoints.
func cpuArchitecture(code int) string {
	switch code {
	case 0:
		return "x86"
	case 5:
		return "arm"
	case 6:
		return "ia64"
	case 9:
		return "x64"
	case 12:
		return "arm64"
	default:
		return "unknown"
	}
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

	payload := map[string]any{}
	if row := first(totals); row != nil {
		putNum(payload, "total_bytes", row["TotalPhysicalMemory"])
	}

	status := boundedStatus(len(moduleRows), MaxMemoryModules)
	if len(moduleRows) > MaxMemoryModules {
		moduleRows = moduleRows[:MaxMemoryModules]
	}
	modules := make([]map[string]any, 0, len(moduleRows))
	for _, row := range moduleRows {
		module := map[string]any{}
		putNum(module, "capacity_bytes", row["Capacity"])
		putNum(module, "speed_mhz", row["Speed"])
		putStr(module, "slot", row["DeviceLocator"])
		putStr(module, "manufacturer", row["Manufacturer"])
		putStr(module, "part_number", row["PartNumber"])
		modules = append(modules, module)
	}
	payload["modules"] = modules
	return payload, status
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

	status := StatusOK
	if len(diskRows) > MaxDisks || len(volumeRows) > MaxVolumes {
		status = StatusPartial
	}
	if len(diskRows) > MaxDisks {
		diskRows = diskRows[:MaxDisks]
	}
	if len(volumeRows) > MaxVolumes {
		volumeRows = volumeRows[:MaxVolumes]
	}

	disks := make([]map[string]any, 0, len(diskRows))
	for _, row := range diskRows {
		disk := map[string]any{}
		putStr(disk, "model", row["Model"])
		putStr(disk, "serial", row["SerialNumber"])
		putNum(disk, "size_bytes", row["Size"])
		putStr(disk, "media_type", row["MediaType"])
		putStr(disk, "bus_type", row["InterfaceType"])
		disks = append(disks, disk)
	}
	volumes := make([]map[string]any, 0, len(volumeRows))
	for _, row := range volumeRows {
		volume := map[string]any{}
		putStr(volume, "mount_point", row["DeviceID"])
		putStr(volume, "label", row["VolumeName"])
		putStr(volume, "filesystem", row["FileSystem"])
		putNum(volume, "size_bytes", row["Size"])
		putNum(volume, "free_bytes", row["FreeSpace"])
		volumes = append(volumes, volume)
	}
	return map[string]any{"disks": disks, "volumes": volumes}, status
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

	status := boundedStatus(len(rows), MaxNetworkAdapters)
	if len(rows) > MaxNetworkAdapters {
		rows = rows[:MaxNetworkAdapters]
	}
	adapters := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		adapter := map[string]any{}
		putStr(adapter, "name", row["Name"])
		putStr(adapter, "mac_address", row["Mac"])
		putStr(adapter, "adapter_type", row["AdapterType"])
		putNum(adapter, "speed_bps", row["Speed"])
		putBool(adapter, "dhcp_enabled", row["Dhcp"])

		raw, _ := row["Addresses"].([]any)
		if len(raw) > MaxAddressesPerAdapter {
			raw = raw[:MaxAddressesPerAdapter]
			status = StatusPartial
		}
		addresses := make([]string, 0, len(raw))
		for _, entry := range raw {
			if text, ok := entry.(string); ok && text != "" {
				addresses = append(addresses, text)
			}
		}
		adapter["addresses"] = addresses
		adapters = append(adapters, adapter)
	}
	return map[string]any{"adapters": adapters}, status
}
