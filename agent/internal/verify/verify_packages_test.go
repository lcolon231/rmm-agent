// SPDX-License-Identifier: AGPL-3.0-only
package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/protocol"
)

// TestVerifyAcceptsPackageKinds guards against the class of bug where a new
// command kind is dispatched and signed by the server but rejected by the
// agent's signature-verification kind allowlist (canonicalCommandBytes runs
// before the signature check, so a missing kind fails closed as "unsupported").
func TestVerifyAcceptsPackageKinds(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		issued = "2026-07-18T12:00:00Z"
		expiry = "2026-07-18T12:05:00Z"
		nonce  = "AAAAAAAAAAAAAAAAAAAAAA"
	)
	cases := []struct {
		kind    string
		payload string
	}{
		{"scan_packages", `{"provider":"winget"}`},
		{"install_packages", `{"provider":"winget","operation":"install","package_ids":["Git.Git"]}`},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			payload := json.RawMessage(tc.payload)
			msg, err := canonicalCommandBytes(
				protocol.CommandEnvelopeV2, protocol.CommandSchemaV1,
				"c1", "a1", tc.kind, payload, issued, expiry, nonce,
			)
			if err != nil {
				t.Fatalf("%s must be an accepted command kind: %v", tc.kind, err)
			}
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
			if err := Verify(
				pub, protocol.CommandEnvelopeV2, protocol.CommandSchemaV1,
				"c1", "a1", tc.kind, payload, issued, expiry, nonce, sig,
			); err != nil {
				t.Fatalf("Verify rejected a valid %s command: %v", tc.kind, err)
			}
		})
	}
}
