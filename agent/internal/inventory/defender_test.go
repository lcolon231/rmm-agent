// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"testing"
	"time"
)

func boolp(v bool) *bool { return &v }

var collected = time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

func TestHealthyDefenderIsActiveAndOK(t *testing.T) {
	payload, status := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode:      "Normal",
		AntivirusEnabled: boolp(true), RealtimeEnabled: boolp(true), TamperProtected: boolp(true),
		SignatureVersion: "1.417.28.0", EngineVersion: "1.1.24070.3",
		SignatureLastUpdated: "2026-07-31T06:00:00Z",
	}, collected)

	if status != StatusOK {
		t.Fatalf("status = %s, want %s", status, StatusOK)
	}
	if payload["provider_state"] != ProviderActive {
		t.Fatalf("provider_state = %v, want %s", payload["provider_state"], ProviderActive)
	}
	if payload["antivirus_signature_age_hours"] != 6 {
		t.Fatalf("age = %v, want 6", payload["antivirus_signature_age_hours"])
	}
}

// The distinction this whole section exists for. A machine running a
// third-party antivirus with Defender stood down is correctly configured; one
// where Defender is simply off is not. Reporting both as "disabled" would
// alarm on every endpoint with a competing product and bury the real ones.
func TestPassiveModeIsNotReportedAsDisabled(t *testing.T) {
	for _, mode := range []string{"Passive", "SxS Passive Mode", "EDR Block Mode", "  passive  "} {
		payload, status := NormalizeDefender(RawDefender{
			Supported: true, Available: true, SecurityCenterQueryable: true,
			RunningMode: mode,
			// Defender reports AntivirusEnabled=false while passive. Reading
			// the flag before the running mode would misclassify this.
			AntivirusEnabled:       boolp(false),
			ThirdPartyProductNames: []string{"Contoso Endpoint Security"},
		}, collected)

		if status != StatusOK {
			t.Fatalf("%q: status = %s, want %s", mode, status, StatusOK)
		}
		if payload["provider_state"] != ProviderPassive {
			t.Fatalf("%q: provider_state = %v, want %s", mode, payload["provider_state"], ProviderPassive)
		}
	}
}

func TestDefenderOffWithNothingElseRegisteredIsDisabled(t *testing.T) {
	payload, _ := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		AntivirusEnabled: boolp(false),
	}, collected)
	if payload["provider_state"] != ProviderDisabled {
		t.Fatalf("provider_state = %v, want %s", payload["provider_state"], ProviderDisabled)
	}
}

func TestThirdPartyProviderIsDistinctFromDisabled(t *testing.T) {
	payload, status := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		AntivirusEnabled:       boolp(false),
		ThirdPartyProductNames: []string{"Contoso Endpoint Security"},
	}, collected)

	if status != StatusOK {
		t.Fatalf("a machine with third-party AV collected fine: status = %s", status)
	}
	if payload["provider_state"] != ProviderThirdParty {
		t.Fatalf("provider_state = %v, want %s", payload["provider_state"], ProviderThirdParty)
	}
	products, _ := payload["third_party_products"].([]string)
	if len(products) != 1 || products[0] != "Contoso Endpoint Security" {
		t.Fatalf("third_party_products = %v", products)
	}
}

func TestUnreadableAndUnsupportedAreDistinguished(t *testing.T) {
	// The cmdlet is missing: this SKU cannot report Defender at all.
	payload, status := NormalizeDefender(RawDefender{Supported: false}, collected)
	if status != StatusUnsupported {
		t.Fatalf("status = %s, want %s", status, StatusUnsupported)
	}
	if len(payload) != 0 {
		t.Fatalf("expected an empty payload, got %v", payload)
	}

	// The cmdlet exists but returned nothing: a real failure to read.
	_, status = NormalizeDefender(RawDefender{Supported: true, Available: false}, collected)
	if status != StatusUnavailable {
		t.Fatalf("status = %s, want %s", status, StatusUnavailable)
	}
}

func TestMissingSecurityCenterDegradesToPartialNotOK(t *testing.T) {
	// Server SKUs have no Security Center. We have Defender's own facts but
	// cannot see registered products, so the picture is incomplete — and an
	// empty product list must not read as "no antivirus installed".
	_, status := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: false,
		RunningMode: "Normal", AntivirusEnabled: boolp(true),
	}, collected)
	if status != StatusPartial {
		t.Fatalf("status = %s, want %s", status, StatusPartial)
	}
}

// Age is computed on the endpoint so that a wrong clock still yields a right
// age: the skew appears on both sides of the subtraction and cancels.
func TestSignatureAgeSurvivesEndpointClockSkew(t *testing.T) {
	skewed := collected.Add(72 * time.Hour) // endpoint clock 3 days fast
	payload, _ := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode:          "Normal",
		SignatureLastUpdated: skewed.Add(-6 * time.Hour).Format(time.RFC3339),
	}, skewed)
	if payload["antivirus_signature_age_hours"] != 6 {
		t.Fatalf("age = %v, want 6 despite clock skew", payload["antivirus_signature_age_hours"])
	}
}

func TestStaleSignaturesReportALargeAgeRatherThanFailing(t *testing.T) {
	payload, status := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode:          "Normal",
		SignatureLastUpdated: collected.Add(-30 * 24 * time.Hour).Format(time.RFC3339),
	}, collected)
	// Staleness is a posture fact for the reader to judge, not a collection
	// failure — the collection succeeded perfectly.
	if status != StatusOK {
		t.Fatalf("status = %s, want %s", status, StatusOK)
	}
	if payload["antivirus_signature_age_hours"] != 720 {
		t.Fatalf("age = %v, want 720", payload["antivirus_signature_age_hours"])
	}
}

func TestUnparseableAndFutureTimestampsAreOmittedNotGuessed(t *testing.T) {
	payload, _ := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode:          "Normal",
		SignatureLastUpdated: "31/07/2026",
		QuickScanEndTime:     "",
		FullScanEndTime:      "not-a-date",
	}, collected)
	for _, key := range []string{
		"antivirus_signature_updated_at", "antivirus_signature_age_hours",
		"last_quick_scan_at", "last_full_scan_at",
	} {
		if _, present := payload[key]; present {
			t.Fatalf("%s should be omitted when unparseable", key)
		}
	}

	// A signature timestamp in the future yields no age rather than a
	// nonsensical negative one.
	payload, _ = NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode:          "Normal",
		SignatureLastUpdated: collected.Add(48 * time.Hour).Format(time.RFC3339),
	}, collected)
	if _, present := payload["antivirus_signature_age_hours"]; present {
		t.Fatalf("a future signature timestamp must not produce an age")
	}
	if _, present := payload["antivirus_signature_updated_at"]; !present {
		t.Fatal("the timestamp itself should still be reported")
	}
}

func TestThirdPartyProductsAreDedupedAndBounded(t *testing.T) {
	names := []string{"Contoso AV", "contoso av  ", "", "Fabrikam Shield"}
	for i := 0; i < 40; i++ {
		names = append(names, "Filler "+itoa(i))
	}
	payload, _ := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		AntivirusEnabled: boolp(false), ThirdPartyProductNames: names,
	}, collected)

	products, _ := payload["third_party_products"].([]string)
	if len(products) != MaxThirdPartyProducts {
		t.Fatalf("kept %d products, want the %d cap", len(products), MaxThirdPartyProducts)
	}
	if products[0] != "Contoso AV" || products[1] != "Fabrikam Shield" {
		t.Fatalf("dedup/order wrong: %v", products[:2])
	}
}

func TestAbsentBooleansAreOmittedRatherThanDefaultedToFalse(t *testing.T) {
	// "We could not read whether real-time protection is on" must not be
	// stored as "real-time protection is off".
	payload, _ := NormalizeDefender(RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode: "Normal",
	}, collected)
	for _, key := range []string{
		"antivirus_enabled", "realtime_protection_enabled", "tamper_protection_enabled",
	} {
		if _, present := payload[key]; present {
			t.Fatalf("%s should be omitted when not reported", key)
		}
	}
}

func TestDefenderPayloadHashesStablyAcrossRuns(t *testing.T) {
	raw := RawDefender{
		Supported: true, Available: true, SecurityCenterQueryable: true,
		RunningMode: "Normal", AntivirusEnabled: boolp(true),
		SignatureVersion: "1.417.28.0", SignatureLastUpdated: "2026-07-31T06:00:00Z",
		ThirdPartyProductNames: []string{"B Product", "A Product"},
	}
	payload, _ := NormalizeDefender(raw, collected)
	first, err := ContentHash(payload)
	if err != nil {
		t.Fatalf("ContentHash: %v", err)
	}
	for i := 0; i < 25; i++ {
		again, err := ContentHash(payload)
		if err != nil {
			t.Fatalf("ContentHash: %v", err)
		}
		if again != first {
			t.Fatalf("hash changed between runs")
		}
	}
}
