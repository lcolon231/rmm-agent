// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"reflect"
	"testing"
)

func TestRowHelpers(t *testing.T) {
	r := map[string]any{"t": true, "f": false, "s": "x", "n": 1.0}
	if !rowBool(r, "t") || rowBool(r, "f") || rowBool(r, "missing") || rowBool(r, "s") {
		t.Fatal("rowBool wrong")
	}
	if p := rowBoolPtr(r, "t"); p == nil || !*p {
		t.Fatal("rowBoolPtr true")
	}
	if p := rowBoolPtr(r, "f"); p == nil || *p {
		t.Fatal("rowBoolPtr false must be non-nil false")
	}
	if rowBoolPtr(r, "missing") != nil || rowBoolPtr(r, "n") != nil {
		t.Fatal("rowBoolPtr absent/wrong type must be nil")
	}
	if rowText(r, "s") != "x" || rowText(r, "n") != "" || rowText(r, "missing") != "" {
		t.Fatal("rowText wrong")
	}
}

func TestRawBitLockerFromRow(t *testing.T) {
	tests := []struct {
		name string
		row  map[string]any
		want RawBitLocker
	}{
		{"empty row", map[string]any{}, RawBitLocker{Volumes: []RawBitLockerVolume{}}},
		{
			"flags and volumes",
			map[string]any{
				"supported": true, "available": true,
				"volumes": []any{
					map[string]any{
						"mount_point": "C:", "protection_status": "On", "volume_status": "FullyEncrypted",
						"encryption_method": "XtsAes256", "encryption_percentage": 100.0, "is_system_volume": true,
					},
					"not-a-map",
					map[string]any{"mount_point": "D:", "encryption_percentage": "x"},
				},
			},
			RawBitLocker{Supported: true, Available: true, Volumes: []RawBitLockerVolume{
				{MountPoint: "C:", ProtectionStatus: "On", VolumeStatus: "FullyEncrypted", EncryptionMethod: "XtsAes256", Percentage: intp(100), IsSystemVolume: boolp(true)},
				{MountPoint: "D:"},
			}},
		},
		{"volumes wrong type", map[string]any{"denied": true, "volumes": "x"}, RawBitLocker{Denied: true, Volumes: []RawBitLockerVolume{}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rawBitLockerFromRow(tt.row); !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestRawSecureBootFromRow(t *testing.T) {
	got := rawSecureBootFromRow(map[string]any{"uefi": true, "available": true, "enabled": false})
	want := RawSecureBoot{UEFI: true, Available: true, Enabled: boolp(false)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if got := rawSecureBootFromRow(map[string]any{"denied": true}); got.Enabled != nil || !got.Denied {
		t.Fatalf("got %#v", got)
	}
}

func TestRawTpmFromRow(t *testing.T) {
	got := rawTpmFromRow(map[string]any{
		"supported": true, "available": true, "present": true, "enabled": true,
		"activated": false, "spec_version": "2.0", "manufacturer": "INTC",
	})
	want := RawTpm{
		Supported: true, Available: true, Present: boolp(true), Enabled: boolp(true),
		Activated: boolp(false), SpecVersion: "2.0", Manufacturer: "INTC",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
	if got := rawTpmFromRow(map[string]any{}); !reflect.DeepEqual(got, RawTpm{}) {
		t.Fatalf("got %#v", got)
	}
}
