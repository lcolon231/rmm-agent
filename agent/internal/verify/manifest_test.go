// SPDX-License-Identifier: AGPL-3.0-only

package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type manifestVectors struct {
	Now         int64             `json:"now"`
	AgentID     string            `json:"agent_id"`
	TrustedKeys map[string]string `json:"trusted_keys"`
	Valid       []struct {
		Name           string                `json:"name"`
		Signed         SignedRoutingManifest `json:"signed"`
		LastIssuedAt   int64                 `json:"last_issued_at"`
		ExpectRelayIDs []string              `json:"expect_relay_ids"`
	} `json:"valid"`
	Invalid []struct {
		Name         string                `json:"name"`
		Signed       SignedRoutingManifest `json:"signed"`
		LastIssuedAt int64                 `json:"last_issued_at"`
		Error        string                `json:"error"`
	} `json:"invalid"`
}

func loadManifestVectors(t *testing.T) (manifestVectors, map[string]ed25519.PublicKey) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "contracts", "test-vectors", "routing-manifest-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors manifestVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	trusted := map[string]ed25519.PublicKey{}
	for keyID, pemKey := range vectors.TrustedKeys {
		key, err := PublicKeyFromPEM(pemKey)
		if err != nil {
			t.Fatal(err)
		}
		trusted[keyID] = key
	}
	return vectors, trusted
}

func TestRoutingManifestVectorsValid(t *testing.T) {
	vectors, trusted := loadManifestVectors(t)
	now := time.Unix(vectors.Now, 0)
	for _, tc := range vectors.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			manifest, err := VerifyRoutingManifest(tc.Signed, trusted, nil, vectors.AgentID, tc.LastIssuedAt, now)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			var relayIDs []string
			for _, route := range manifest.Routes {
				if route.Kind == "relay" {
					relayIDs = append(relayIDs, route.RelayID)
				}
			}
			if len(relayIDs) != len(tc.ExpectRelayIDs) {
				t.Fatalf("relay routes = %v, want %v", relayIDs, tc.ExpectRelayIDs)
			}
			for i := range relayIDs {
				if relayIDs[i] != tc.ExpectRelayIDs[i] {
					t.Fatalf("relay routes = %v, want %v", relayIDs, tc.ExpectRelayIDs)
				}
			}
		})
	}
}

func TestRoutingManifestVectorsInvalid(t *testing.T) {
	vectors, trusted := loadManifestVectors(t)
	now := time.Unix(vectors.Now, 0)
	for _, tc := range vectors.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := VerifyRoutingManifest(tc.Signed, trusted, nil, vectors.AgentID, tc.LastIssuedAt, now)
			var me *ManifestError
			if !errors.As(err, &me) || me.Code != tc.Error {
				t.Fatalf("err = %v, want %s", err, tc.Error)
			}
		})
	}
}

// A manifest signed only by a key the agent has not learned yet (an incoming
// key, or one a relay made up) must never be accepted on its own word.
func TestRoutingManifestRefusesSignerOutsideTrustedSet(t *testing.T) {
	vectors, trusted := loadManifestVectors(t)
	onlyNew := map[string]ed25519.PublicKey{"new": trusted["new"]}
	signedByOld := vectors.Valid[1].Signed // signed by "old" only
	_, err := VerifyRoutingManifest(signedByOld, onlyNew, nil, vectors.AgentID, 0, time.Unix(vectors.Now, 0))
	var me *ManifestError
	if !errors.As(err, &me) || me.Code != "signature_untrusted" {
		t.Fatalf("err = %v, want signature_untrusted", err)
	}
}

// Single-key deployments label their key with a configured ID the agent may
// never have learned; the legacy key must still verify.
func TestRoutingManifestAcceptsLegacySingleKey(t *testing.T) {
	vectors, trusted := loadManifestVectors(t)
	_, err := VerifyRoutingManifest(
		vectors.Valid[1].Signed, nil, trusted["old"], vectors.AgentID, 0, time.Unix(vectors.Now, 0),
	)
	if err != nil {
		t.Fatalf("verify with legacy key: %v", err)
	}
}

func TestRoutingManifestStaleAfterExpiry(t *testing.T) {
	vectors, trusted := loadManifestVectors(t)
	later := time.Unix(vectors.Now, 0).Add(2 * time.Hour)
	_, err := VerifyRoutingManifest(vectors.Valid[0].Signed, trusted, nil, vectors.AgentID, 0, later)
	var me *ManifestError
	if !errors.As(err, &me) || me.Code != "expired" {
		t.Fatalf("err = %v, want expired", err)
	}
}
