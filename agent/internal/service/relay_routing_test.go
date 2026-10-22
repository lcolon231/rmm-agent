// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/config"
	"github.com/lcolon231/rmm/agent/internal/verify"
)

func pemFor(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func signedManifest(t *testing.T, signer ed25519.PrivateKey, keyID string, doc map[string]any) *verify.SignedRoutingManifest {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(signer, append([]byte("nodelink-agent-routing-v1:"), raw...))
	return &verify.SignedRoutingManifest{
		ManifestB64: base64.StdEncoding.EncodeToString(raw),
		Signatures: []verify.ManifestSignature{
			{KeyID: keyID, Signature: base64.StdEncoding.EncodeToString(sig)},
		},
	}
}

func relaySession(t *testing.T) (*Agent, *session, ed25519.PrivateKey) {
	t.Helper()
	a, s, _, _ := newTestSession(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.pubKeys = map[string]ed25519.PublicKey{"k1": pub}
	s.identity = &config.Identity{
		AgentID:           s.agentID,
		CommandPublicKeys: map[string]string{"k1": pemFor(t, pub)},
	}
	s.identityPath = filepath.Join(t.TempDir(), "identity.json")
	return a, s, priv
}

func manifestDoc(agentID string, issued time.Time, keys map[string]string) map[string]any {
	return map[string]any{
		"manifest_version": "routing-manifest-v1",
		"agent_id":         agentID,
		"issued_at":        issued.Unix(),
		"expires_at":       issued.Add(time.Hour).Unix(),
		"residency_mode":   "preferred",
		"home_region":      "eu-west",
		"routes": []any{
			map[string]any{
				"kind":          "relay",
				"relay_id":      "7d2e9a40-1f6b-4b8e-8c3a-2e5f9b1d4c22",
				"region":        "eu-west",
				"base_url":      "https://euw1.relay.example",
				"tls_spki_pins": []string{},
			},
			map[string]any{"kind": "origin"},
		},
		"command_public_keys": keys,
	}
}

// The core mutual-trust property: a relay terminates TLS, so an unsigned key
// bundle it hands back must never replace the keys that authorize commands.
func TestRelayedUnsignedKeyBundleIsIgnored(t *testing.T) {
	a, s, _ := relaySession(t)
	attackerPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ack := &client.HeartbeatAck{CommandPublicKeys: map[string]string{"evil": pemFor(t, attackerPub)}}
	if err := a.applyRoutingAndKeys(s, ack, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.pubKeys["evil"]; ok || len(s.pubKeys) != 1 {
		t.Fatalf("relay-injected key was trusted: %v", s.pubKeys)
	}
}

func TestOriginUnsignedKeyBundleKeepsLegacyBehavior(t *testing.T) {
	a, s, _ := relaySession(t)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	ack := &client.HeartbeatAck{CommandPublicKeys: map[string]string{"k2": pemFor(t, nextPub)}}
	if err := a.applyRoutingAndKeys(s, ack, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.pubKeys["k2"]; !ok {
		t.Fatal("origin key bundle was not applied")
	}
}

func TestVerifiedManifestRotatesKeysAndInstallsRoutes(t *testing.T) {
	a, s, priv := relaySession(t)
	nextPub, _, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]string{"k1": s.identity.CommandPublicKeys["k1"], "k2": pemFor(t, nextPub)}
	now := time.Now()
	ack := &client.HeartbeatAck{RoutingManifest: signedManifest(t, priv, "k1", manifestDoc(s.agentID, now, keys))}
	if err := a.applyRoutingAndKeys(s, ack, true, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.pubKeys["k2"]; !ok {
		t.Fatal("signed rotation did not add the incoming key")
	}
	stored := s.identity.RoutingManifest
	if stored == nil || len(stored.Routes) != 1 || stored.Routes[0].Region != "eu-west" {
		t.Fatalf("routes not persisted: %+v", stored)
	}
	reloaded, err := config.LoadIdentity(s.identityPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.RoutingManifest == nil || reloaded.RoutingManifest.IssuedAt != now.Unix() {
		t.Fatalf("manifest not saved with the identity: %+v", reloaded.RoutingManifest)
	}
}

func TestManifestFromUntrustedSignerOrRollbackChangesNothing(t *testing.T) {
	a, s, priv := relaySession(t)
	now := time.Now()
	keys := map[string]string{"k1": s.identity.CommandPublicKeys["k1"]}
	first := &client.HeartbeatAck{RoutingManifest: signedManifest(t, priv, "k1", manifestDoc(s.agentID, now, keys))}
	if err := a.applyRoutingAndKeys(s, first, true, now); err != nil {
		t.Fatal(err)
	}

	// Rollback: an older, validly signed manifest replayed by a relay.
	older := &client.HeartbeatAck{RoutingManifest: signedManifest(
		t, priv, "k1", manifestDoc(s.agentID, now.Add(-10*time.Minute), keys),
	)}
	if err := a.applyRoutingAndKeys(s, older, true, now); err != nil {
		t.Fatal(err)
	}
	if s.identity.RoutingManifest.IssuedAt != now.Unix() {
		t.Fatal("a rolled-back manifest replaced the current one")
	}

	// Untrusted signer offering its own key.
	attackerPub, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged := &client.HeartbeatAck{RoutingManifest: signedManifest(
		t, attackerPriv, "k1", manifestDoc(s.agentID, now.Add(time.Minute), map[string]string{"evil": pemFor(t, attackerPub)}),
	)}
	if err := a.applyRoutingAndKeys(s, forged, true, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.pubKeys["evil"]; ok {
		t.Fatal("a forged manifest's key was trusted")
	}
}
