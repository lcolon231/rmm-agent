// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func intp(v int) *int { return &v }

// The collector must have no path by which a recovery key could be read. This
// asserts against the actual PowerShell source rather than the parsed output,
// because the guarantee is "never fetched", not "fetched and then dropped".
func TestBitLockerCollectorNeverAsksForRecoveryKeyMaterial(t *testing.T) {
	forbidden := []string{
		"KeyProtector", "RecoveryPassword", "RecoveryKey",
		"BitLockerKey", "Backup-BitLocker", "-RecoveryPasswordProtector",
	}
	for _, term := range forbidden {
		if strings.Contains(bitlockerScript, term) {
			t.Fatalf("the BitLocker query references %q; recovery key material "+
				"must never be requested", term)
		}
	}
	// And the property list is an allowlist, so nothing can arrive by accident.
	if !strings.Contains(bitlockerScript, "mount_point") {
		t.Fatal("expected an explicit property allowlist")
	}
}

func TestBitLockerPayloadHasNowhereToPutASecret(t *testing.T) {
	// Even a collector bug that produced key material must not survive
	// serialization: the normalizer emits a fixed key set.
	payload, _ := NormalizeBitLocker(RawBitLocker{
		Supported: true, Available: true,
		Volumes: []RawBitLockerVolume{{
			MountPoint: "C:", ProtectionStatus: "On", VolumeStatus: "FullyEncrypted",
			EncryptionMethod: "XtsAes256", Percentage: intp(100),
		}},
	})
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	allowed := map[string]struct{}{
		"volumes": {}, "mount_point": {}, "protection_status": {},
		"volume_status": {}, "encryption_method": {},
		"encryption_percentage": {}, "is_system_volume": {},
	}
	var round map[string]any
	if err := json.Unmarshal(encoded, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, volume := range round["volumes"].([]any) {
		for key := range volume.(map[string]any) {
			if _, ok := allowed[key]; !ok {
				t.Fatalf("unexpected key %q in a BitLocker volume payload", key)
			}
		}
	}
}

func TestBitLockerPermissionDenialIsNotAnEmptyVolumeList(t *testing.T) {
	// An empty list with an "ok" status would read as "nothing on this machine
	// is encrypted" — the most dangerous possible misreading of a permission
	// failure.
	payload, status := NormalizeBitLocker(RawBitLocker{Supported: true, Denied: true})
	if status != StatusPermissionDenied {
		t.Fatalf("status = %s, want %s", status, StatusPermissionDenied)
	}
	if len(payload) != 0 {
		t.Fatalf("expected no payload for a denied read, got %v", payload)
	}
}

func TestBitLockerUnsupportedUnavailableAndDeniedAreDistinct(t *testing.T) {
	cases := []struct {
		raw  RawBitLocker
		want string
	}{
		{RawBitLocker{Supported: false}, StatusUnsupported},
		{RawBitLocker{Supported: true, Denied: true}, StatusPermissionDenied},
		{RawBitLocker{Supported: true, Available: false}, StatusUnavailable},
		{RawBitLocker{Supported: true, Available: true}, StatusOK},
	}
	for _, tc := range cases {
		if _, status := NormalizeBitLocker(tc.raw); status != tc.want {
			t.Fatalf("status = %s, want %s for %+v", status, tc.want, tc.raw)
		}
	}
}

func TestUnrecognizedProtectionStatusIsUnknownNotOff(t *testing.T) {
	// Claiming a volume is unprotected when we could not tell is the dangerous
	// direction of this error.
	for _, value := range []string{"", "Suspended", "garbage", "2"} {
		payload, _ := NormalizeBitLocker(RawBitLocker{
			Supported: true, Available: true,
			Volumes: []RawBitLockerVolume{{MountPoint: "C:", ProtectionStatus: value}},
		})
		volumes := payload["volumes"].([]map[string]any)
		if volumes[0]["protection_status"] != ProtectionUnknown {
			t.Fatalf("%q -> %v, want %s", value, volumes[0]["protection_status"], ProtectionUnknown)
		}
	}
	// The values it does recognize still map correctly.
	payload, _ := NormalizeBitLocker(RawBitLocker{
		Supported: true, Available: true,
		Volumes: []RawBitLockerVolume{
			{MountPoint: "C:", ProtectionStatus: "On"},
			{MountPoint: "D:", ProtectionStatus: "off"},
		},
	})
	volumes := payload["volumes"].([]map[string]any)
	if volumes[0]["protection_status"] != ProtectionOn || volumes[1]["protection_status"] != ProtectionOff {
		t.Fatalf("recognized values mapped wrongly: %v", volumes)
	}
}

func TestBitLockerVolumesAreBounded(t *testing.T) {
	raw := RawBitLocker{Supported: true, Available: true}
	for i := 0; i < MaxVolumes+20; i++ {
		raw.Volumes = append(raw.Volumes, RawBitLockerVolume{MountPoint: "X:"})
	}
	payload, status := NormalizeBitLocker(raw)
	if status != StatusPartial {
		t.Fatalf("status = %s, want %s", status, StatusPartial)
	}
	if got := len(payload["volumes"].([]map[string]any)); got != MaxVolumes {
		t.Fatalf("kept %d volumes, want %d", got, MaxVolumes)
	}
}

func TestOutOfRangeEncryptionPercentageIsOmitted(t *testing.T) {
	payload, _ := NormalizeBitLocker(RawBitLocker{
		Supported: true, Available: true,
		Volumes: []RawBitLockerVolume{{MountPoint: "C:", Percentage: intp(150)}},
	})
	volume := payload["volumes"].([]map[string]any)[0]
	if _, present := volume["encryption_percentage"]; present {
		t.Fatal("an out-of-range percentage should be omitted, not stored")
	}
}

// The Secure Boot analogue of the passive-Defender problem: a legacy-BIOS
// machine cannot have Secure Boot, and reporting it as "disabled" would flag a
// machine behaving correctly for its firmware.
func TestLegacyBiosIsUnsupportedNotDisabled(t *testing.T) {
	payload, status := NormalizeSecureBoot(RawSecureBoot{UEFI: false})
	if status != StatusUnsupported {
		t.Fatalf("status = %s, want %s", status, StatusUnsupported)
	}
	if payload["firmware_type"] != FirmwareBIOS {
		t.Fatalf("firmware_type = %v, want %s", payload["firmware_type"], FirmwareBIOS)
	}
	if _, present := payload["enabled"]; present {
		t.Fatal("a BIOS machine must not report a Secure Boot enabled flag at all")
	}
}

func TestSecureBootStatesAreDistinguished(t *testing.T) {
	on := true
	off := false

	payload, status := NormalizeSecureBoot(RawSecureBoot{UEFI: true, Available: true, Enabled: &on})
	if status != StatusOK || payload["enabled"] != true {
		t.Fatalf("enabled case: status=%s payload=%v", status, payload)
	}

	// Genuinely disabled on UEFI is a real, reportable posture.
	payload, status = NormalizeSecureBoot(RawSecureBoot{UEFI: true, Available: true, Enabled: &off})
	if status != StatusOK || payload["enabled"] != false {
		t.Fatalf("disabled case: status=%s payload=%v", status, payload)
	}

	if _, status = NormalizeSecureBoot(RawSecureBoot{UEFI: true, Denied: true}); status != StatusPermissionDenied {
		t.Fatalf("denied case: status=%s", status)
	}
	if _, status = NormalizeSecureBoot(RawSecureBoot{UEFI: true, Available: false}); status != StatusUnavailable {
		t.Fatalf("unavailable case: status=%s", status)
	}
}

func TestAbsentTpmIsASuccessfulReadingNotAFailure(t *testing.T) {
	absent := false
	payload, status := NormalizeTpm(RawTpm{
		Supported: true, Available: true, Present: &absent,
	})
	// "This machine has no TPM" is exactly why it cannot use a TPM-backed
	// BitLocker protector — a fact worth recording, not an error.
	if status != StatusOK {
		t.Fatalf("status = %s, want %s", status, StatusOK)
	}
	if payload["present"] != false {
		t.Fatalf("present = %v, want false", payload["present"])
	}
}

func TestTpmReadinessIsOnlyAssertedWhenFullyKnown(t *testing.T) {
	yes := true
	no := false

	// Every component known and true.
	payload, _ := NormalizeTpm(RawTpm{
		Supported: true, Available: true,
		Present: &yes, Enabled: &yes, Activated: &yes, Owned: &yes,
	})
	if payload["ready"] != true {
		t.Fatalf("ready = %v, want true", payload["ready"])
	}

	// One component false: ready is false, not omitted.
	payload, _ = NormalizeTpm(RawTpm{
		Supported: true, Available: true,
		Present: &yes, Enabled: &yes, Activated: &yes, Owned: &no,
	})
	if payload["ready"] != false {
		t.Fatalf("ready = %v, want false", payload["ready"])
	}

	// One component unknown: readiness is not claimed either way, because
	// asserting it from partial information would overstate the posture.
	payload, _ = NormalizeTpm(RawTpm{
		Supported: true, Available: true,
		Present: &yes, Enabled: &yes, Activated: &yes,
	})
	if _, present := payload["ready"]; present {
		t.Fatal("ready must not be derived from incomplete information")
	}
}

func TestTpmUnsupportedDeniedAndUnavailableAreDistinct(t *testing.T) {
	if _, status := NormalizeTpm(RawTpm{Supported: false}); status != StatusUnsupported {
		t.Fatalf("status = %s, want %s", status, StatusUnsupported)
	}
	if _, status := NormalizeTpm(RawTpm{Supported: true, Denied: true}); status != StatusPermissionDenied {
		t.Fatalf("status = %s, want %s", status, StatusPermissionDenied)
	}
	if _, status := NormalizeTpm(RawTpm{Supported: true, Available: false}); status != StatusUnavailable {
		t.Fatalf("status = %s, want %s", status, StatusUnavailable)
	}
}

func TestPlatformSecurityPayloadsHashStably(t *testing.T) {
	yes := true
	payloads := []map[string]any{}
	bitlocker, _ := NormalizeBitLocker(RawBitLocker{
		Supported: true, Available: true,
		Volumes: []RawBitLockerVolume{{MountPoint: "C:", ProtectionStatus: "On"}},
	})
	secureBoot, _ := NormalizeSecureBoot(RawSecureBoot{UEFI: true, Available: true, Enabled: &yes})
	tpm, _ := NormalizeTpm(RawTpm{Supported: true, Available: true, Present: &yes})
	payloads = append(payloads, bitlocker, secureBoot, tpm)

	for _, payload := range payloads {
		first, err := ContentHash(payload)
		if err != nil {
			t.Fatalf("ContentHash: %v", err)
		}
		for i := 0; i < 20; i++ {
			again, err := ContentHash(payload)
			if err != nil {
				t.Fatalf("ContentHash: %v", err)
			}
			if again != first {
				t.Fatal("hash changed between runs")
			}
		}
	}
}
