// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import "strconv"

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
		// rather than risking a lossy float round-trip through JSON.
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

// NormalizeSystem builds the system section from decoded Win32 rows.
func NormalizeSystem(rows []map[string]any) (map[string]any, string) {
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

// NormalizeCPU builds the cpu section from decoded Win32_Processor rows.
func NormalizeCPU(rows []map[string]any) (map[string]any, string) {
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

// NormalizeMemory builds the memory section from the total-memory rows and the
// physical-module rows, bounding the module list at MaxMemoryModules.
func NormalizeMemory(totals, moduleRows []map[string]any) (map[string]any, string) {
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

// NormalizeStorage builds the storage section from disk and volume rows,
// bounding each list.
func NormalizeStorage(diskRows, volumeRows []map[string]any) (map[string]any, string) {
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

// NormalizeNetwork builds the network section from adapter rows, bounding the
// adapter list and each adapter's address list.
func NormalizeNetwork(rows []map[string]any) (map[string]any, string) {
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
