//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
)

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

func collectBitLocker(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, bitlockerScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}

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

	return NormalizeBitLocker(RawBitLocker{
		Supported: rowBool(row, "supported"),
		Denied:    rowBool(row, "denied"),
		Available: rowBool(row, "available"),
		Volumes:   volumes,
	})
}

func collectSecureBoot(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, secureBootScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	return NormalizeSecureBoot(RawSecureBoot{
		UEFI:      rowBool(row, "uefi"),
		Denied:    rowBool(row, "denied"),
		Available: rowBool(row, "available"),
		Enabled:   rowBoolPtr(row, "enabled"),
	})
}

func collectTpm(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, tpmScript)
	if err != nil {
		return nil, StatusUnavailable
	}
	row := first(rows)
	if row == nil {
		return nil, StatusUnavailable
	}
	return NormalizeTpm(RawTpm{
		Supported:    rowBool(row, "supported"),
		Denied:       rowBool(row, "denied"),
		Available:    rowBool(row, "available"),
		Present:      rowBoolPtr(row, "present"),
		Enabled:      rowBoolPtr(row, "enabled"),
		Activated:    rowBoolPtr(row, "activated"),
		Owned:        rowBoolPtr(row, "owned"),
		SpecVersion:  rowText(row, "spec_version"),
		Manufacturer: rowText(row, "manufacturer"),
	})
}
