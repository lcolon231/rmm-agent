// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"strings"
	"time"
)

// Provider states. These mirror the server's DefenderProviderState.
const (
	ProviderActive     = "active"
	ProviderPassive    = "passive"
	ProviderThirdParty = "third_party"
	ProviderDisabled   = "disabled"
	ProviderUnknown    = "unknown"
)

// MaxThirdPartyProducts mirrors the server bound.
const MaxThirdPartyProducts = 16

// RawDefender is what the endpoint reported, before interpretation. Keeping
// the raw shape separate from the wire shape puts every judgement call —
// which state is this machine actually in, is the signature stale — in code
// that can be tested without Windows.
type RawDefender struct {
	// Available is false when Get-MpComputerStatus could not be run at all.
	Available bool
	// Supported is false when the Defender cmdlets do not exist on this SKU.
	Supported bool

	RunningMode             string
	AntivirusEnabled        *bool
	RealtimeEnabled         *bool
	TamperProtected         *bool
	SignatureVersion        string
	SignatureLastUpdated    string
	EngineVersion           string
	ProductVersion          string
	QuickScanEndTime        string
	FullScanEndTime         string
	ThirdPartyProductNames  []string
	SecurityCenterQueryable bool
}

// deriveProviderState decides what role Defender is playing.
//
// Order matters. A stood-down running mode is checked before the enabled flag,
// because Defender in passive mode reports AntivirusEnabled=false while being
// exactly what a correctly configured machine with a third-party product looks
// like. Reading that as "disabled" would raise an alarm on every such endpoint
// and bury the genuinely unprotected ones.
func deriveProviderState(raw RawDefender) string {
	switch normalizeRunningMode(raw.RunningMode) {
	case "normal":
		return ProviderActive
	case "passive", "sxs passive mode", "edr block mode":
		return ProviderPassive
	}

	// No usable running mode. Fall back to the enabled flag plus whatever
	// Security Center says is registered.
	hasThirdParty := len(raw.ThirdPartyProductNames) > 0
	if raw.AntivirusEnabled != nil && *raw.AntivirusEnabled {
		return ProviderActive
	}
	if hasThirdParty {
		return ProviderThirdParty
	}
	if raw.AntivirusEnabled != nil {
		// Explicitly off, and nothing else registered to take over.
		return ProviderDisabled
	}
	return ProviderUnknown
}

func normalizeRunningMode(mode string) string {
	return strings.ToLower(strings.Join(strings.Fields(mode), " "))
}

// parseDefenderTime accepts the round-trip form the collector emits. An
// unparseable value yields no timestamp rather than a guess, matching how
// install dates are handled for software.
func parseDefenderTime(value string) (time.Time, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC(), true
}

// signatureAgeHours is computed on the endpoint, from the endpoint's own clock.
//
// That is deliberate: if the machine's clock is wrong, the reported update
// timestamp is wrong too, but the *age* stays correct because the skew appears
// on both sides of the subtraction. Age is also the value staleness is
// actually judged on. A negative interval (signature timestamp in the future)
// is reported as no age rather than as a nonsensical negative.
func signatureAgeHours(updatedAt time.Time, collectedAt time.Time) (int, bool) {
	if updatedAt.IsZero() {
		return 0, false
	}
	delta := collectedAt.Sub(updatedAt)
	if delta < 0 {
		return 0, false
	}
	return int(delta.Hours()), true
}

func boundedProducts(names []string) []string {
	seen := make(map[string]struct{}, len(names))
	out := make([]string, 0, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
		if len(out) == MaxThirdPartyProducts {
			break
		}
	}
	return out
}

// NormalizeDefender turns a raw reading into the wire payload and the section
// status.
//
// The status answers "could we collect this?", while provider_state answers
// "what is the machine's actual posture?". They are independent: a successful
// collection reporting a third-party antivirus is `ok`, not a failure.
func NormalizeDefender(raw RawDefender, collectedAt time.Time) (map[string]any, string) {
	if !raw.Supported {
		return map[string]any{}, StatusUnsupported
	}
	if !raw.Available {
		return map[string]any{}, StatusUnavailable
	}

	payload := map[string]any{
		"provider_state": deriveProviderState(raw),
	}
	if raw.AntivirusEnabled != nil {
		payload["antivirus_enabled"] = *raw.AntivirusEnabled
	}
	if raw.RealtimeEnabled != nil {
		payload["realtime_protection_enabled"] = *raw.RealtimeEnabled
	}
	if raw.TamperProtected != nil {
		payload["tamper_protection_enabled"] = *raw.TamperProtected
	}
	if version := strings.TrimSpace(raw.SignatureVersion); version != "" {
		payload["antivirus_signature_version"] = version
	}
	if version := strings.TrimSpace(raw.EngineVersion); version != "" {
		payload["engine_version"] = version
	}
	if version := strings.TrimSpace(raw.ProductVersion); version != "" {
		payload["product_version"] = version
	}
	if updated, ok := parseDefenderTime(raw.SignatureLastUpdated); ok {
		payload["antivirus_signature_updated_at"] = updated.Format(time.RFC3339)
		if age, ok := signatureAgeHours(updated, collectedAt); ok {
			payload["antivirus_signature_age_hours"] = age
		}
	}
	if scanned, ok := parseDefenderTime(raw.QuickScanEndTime); ok {
		payload["last_quick_scan_at"] = scanned.Format(time.RFC3339)
	}
	if scanned, ok := parseDefenderTime(raw.FullScanEndTime); ok {
		payload["last_full_scan_at"] = scanned.Format(time.RFC3339)
	}

	products := boundedProducts(raw.ThirdPartyProductNames)
	if len(products) > 0 {
		payload["third_party_products"] = products
	}

	// Security Center is absent on Server SKUs. Report the Defender facts we
	// do have as partial rather than claiming a complete security picture.
	if !raw.SecurityCenterQueryable {
		return payload, StatusPartial
	}
	return payload, StatusOK
}
