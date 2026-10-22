// SPDX-License-Identifier: AGPL-3.0-only

package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Routing manifests (issue #87) carry the ordered relay routes and the command
// key bundle to an agent that may be talking to the control plane through a
// relay. The relay is never trusted for content, so the agent acts only on a
// manifest signed by a key it already trusts. The server sends the exact signed
// bytes (base64), so the agent verifies bytes and never re-canonicalizes JSON.
const (
	RoutingManifestVersion = "routing-manifest-v1"
	routingManifestContext = "nodelink-agent-routing-v1:"
	maxManifestBytes       = 64 * 1024
	maxManifestRoutes      = 16
	maxManifestLifetime    = 24 * time.Hour
	maxManifestSignatures  = 16
)

var (
	keyIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	regionPattern  = regexp.MustCompile(`^[a-z0-9-]{0,32}$`)
	relayIDPattern = regexp.MustCompile(`^[0-9a-f-]{36}$`)
)

// SignedRoutingManifest is the heartbeat's routing_manifest field.
type SignedRoutingManifest struct {
	ManifestB64 string              `json:"manifest_b64"`
	Signatures  []ManifestSignature `json:"signatures"`
}

// ManifestSignature is one keyring key's signature over the manifest bytes.
type ManifestSignature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// RoutingManifest is the verified document.
type RoutingManifest struct {
	ManifestVersion   string            `json:"manifest_version"`
	AgentID           string            `json:"agent_id"`
	IssuedAt          int64             `json:"issued_at"`
	ExpiresAt         int64             `json:"expires_at"`
	ResidencyMode     string            `json:"residency_mode"`
	HomeRegion        string            `json:"home_region"`
	Routes            []ManifestRoute   `json:"routes"`
	CommandPublicKeys map[string]string `json:"command_public_keys"`
}

// ManifestRoute is one route, best first. Kind "origin" means the agent's
// enrolled server URL and carries no other field.
type ManifestRoute struct {
	Kind        string   `json:"kind"`
	RelayID     string   `json:"relay_id,omitempty"`
	Region      string   `json:"region,omitempty"`
	BaseURL     string   `json:"base_url,omitempty"`
	TLSSPKIPins []string `json:"tls_spki_pins,omitempty"`
}

// ManifestError is a stable, loggable refusal reason.
type ManifestError struct{ Code string }

func (e *ManifestError) Error() string { return "routing manifest refused: " + e.Code }

func manifestErr(code string) error { return &ManifestError{Code: code} }

// VerifyRoutingManifest authenticates and validates a signed manifest.
//
// trusted holds the command keys the agent already trusts by key ID. legacy is
// the single pre-keyring command key (may be nil); it is tried against every
// signature because a single-key server labels it with a configured key ID
// the agent never learned. lastIssuedAt is the issued_at of the manifest the
// agent currently holds (0 for none); an older manifest is a rollback and is
// refused, so a relay cannot replay a stale route set or key bundle.
func VerifyRoutingManifest(
	signed SignedRoutingManifest,
	trusted map[string]ed25519.PublicKey,
	legacy ed25519.PublicKey,
	agentID string,
	lastIssuedAt int64,
	now time.Time,
) (*RoutingManifest, error) {
	raw, err := base64.StdEncoding.DecodeString(signed.ManifestB64)
	if err != nil || len(raw) == 0 {
		return nil, manifestErr("malformed")
	}
	if len(raw) > maxManifestBytes {
		return nil, manifestErr("too_large")
	}
	if len(signed.Signatures) == 0 || len(signed.Signatures) > maxManifestSignatures {
		return nil, manifestErr("signature_missing")
	}
	message := append([]byte(routingManifestContext), raw...)
	verified := false
	for _, item := range signed.Signatures {
		if !keyIDPattern.MatchString(item.KeyID) {
			continue
		}
		sig, decodeErr := base64.StdEncoding.DecodeString(item.Signature)
		if decodeErr != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		if key, ok := trusted[item.KeyID]; ok && ed25519.Verify(key, message, sig) {
			verified = true
			break
		}
		if legacy != nil && ed25519.Verify(legacy, message, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, manifestErr("signature_untrusted")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest RoutingManifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, manifestErr("malformed")
	}
	if manifest.ManifestVersion != RoutingManifestVersion {
		return nil, manifestErr("unsupported_version")
	}
	if manifest.AgentID != agentID {
		return nil, manifestErr("wrong_agent")
	}
	nowUnix := now.Unix()
	if manifest.ExpiresAt <= manifest.IssuedAt ||
		time.Duration(manifest.ExpiresAt-manifest.IssuedAt)*time.Second > maxManifestLifetime {
		return nil, manifestErr("lifetime_invalid")
	}
	if manifest.IssuedAt > nowUnix+int64(maxIssuedAtClockSkew/time.Second) {
		return nil, manifestErr("issued_in_future")
	}
	if manifest.ExpiresAt <= nowUnix {
		return nil, manifestErr("expired")
	}
	if manifest.IssuedAt < lastIssuedAt {
		return nil, manifestErr("rollback")
	}
	switch manifest.ResidencyMode {
	case "none", "preferred", "strict":
	default:
		return nil, manifestErr("residency_mode_invalid")
	}
	if !regionPattern.MatchString(manifest.HomeRegion) {
		return nil, manifestErr("region_invalid")
	}
	if len(manifest.Routes) == 0 || len(manifest.Routes) > maxManifestRoutes {
		return nil, manifestErr("routes_invalid")
	}
	for _, route := range manifest.Routes {
		if err := validateRoute(route); err != nil {
			return nil, err
		}
	}
	if len(manifest.CommandPublicKeys) == 0 {
		return nil, manifestErr("keys_missing")
	}
	for keyID, pemKey := range manifest.CommandPublicKeys {
		if !keyIDPattern.MatchString(keyID) {
			return nil, manifestErr("keys_invalid")
		}
		if _, err := PublicKeyFromPEM(pemKey); err != nil {
			return nil, manifestErr("keys_invalid")
		}
	}
	return &manifest, nil
}

func validateRoute(route ManifestRoute) error {
	switch route.Kind {
	case "origin":
		if route.RelayID != "" || route.BaseURL != "" || len(route.TLSSPKIPins) > 0 {
			return manifestErr("route_invalid")
		}
		return nil
	case "relay":
	default:
		return manifestErr("route_invalid")
	}
	if !relayIDPattern.MatchString(route.RelayID) || !regionPattern.MatchString(route.Region) {
		return manifestErr("route_invalid")
	}
	parsed, err := url.Parse(route.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || strings.Trim(parsed.Path, "/") != "" {
		return manifestErr("route_invalid")
	}
	if len(route.TLSSPKIPins) > 4 {
		return manifestErr("route_invalid")
	}
	return nil
}

// String is for logs: it never includes key material.
func (m *RoutingManifest) String() string {
	return fmt.Sprintf("routing manifest issued=%d expires=%d mode=%s routes=%d",
		m.IssuedAt, m.ExpiresAt, m.ResidencyMode, len(m.Routes))
}
