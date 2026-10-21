// SPDX-License-Identifier: AGPL-3.0-only

package inventory

func rowBool(row map[string]any, key string) bool {
	value, _ := row[key].(bool)
	return value
}

func rowBoolPtr(row map[string]any, key string) *bool {
	value, ok := row[key].(bool)
	if !ok {
		return nil
	}
	return &value
}

func rowText(row map[string]any, key string) string {
	value, _ := row[key].(string)
	return value
}

// rawBitLockerFromRow converts one decoded BitLocker script row into the raw
// reading consumed by NormalizeBitLocker.
func rawBitLockerFromRow(row map[string]any) RawBitLocker {
	volumes := []RawBitLockerVolume{}
	if raw, ok := row["volumes"].([]any); ok {
		for _, entry := range raw {
			volume, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			parsed := RawBitLockerVolume{
				MountPoint:       rowText(volume, "mount_point"),
				ProtectionStatus: rowText(volume, "protection_status"),
				VolumeStatus:     rowText(volume, "volume_status"),
				EncryptionMethod: rowText(volume, "encryption_method"),
				IsSystemVolume:   rowBoolPtr(volume, "is_system_volume"),
			}
			if percent, ok := volume["encryption_percentage"].(float64); ok {
				value := int(percent)
				parsed.Percentage = &value
			}
			volumes = append(volumes, parsed)
		}
	}
	return RawBitLocker{
		Supported: rowBool(row, "supported"),
		Denied:    rowBool(row, "denied"),
		Available: rowBool(row, "available"),
		Volumes:   volumes,
	}
}

func rawSecureBootFromRow(row map[string]any) RawSecureBoot {
	return RawSecureBoot{
		UEFI:      rowBool(row, "uefi"),
		Denied:    rowBool(row, "denied"),
		Available: rowBool(row, "available"),
		Enabled:   rowBoolPtr(row, "enabled"),
	}
}

func rawTpmFromRow(row map[string]any) RawTpm {
	return RawTpm{
		Supported:    rowBool(row, "supported"),
		Denied:       rowBool(row, "denied"),
		Available:    rowBool(row, "available"),
		Present:      rowBoolPtr(row, "present"),
		Enabled:      rowBoolPtr(row, "enabled"),
		Activated:    rowBoolPtr(row, "activated"),
		Owned:        rowBoolPtr(row, "owned"),
		SpecVersion:  rowText(row, "spec_version"),
		Manufacturer: rowText(row, "manufacturer"),
	}
}
