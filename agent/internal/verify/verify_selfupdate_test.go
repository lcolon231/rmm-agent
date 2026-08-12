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

// TestVerifyAcceptsSelfUpdateKinds guards the class of bug where the server
// signs and dispatches a new kind that the agent's verification allowlist
// rejects. canonicalCommandBytes runs before the signature check, so a missing
// kind fails closed as "unsupported" — correct, but it would silently make
// self-update undeliverable (issue #63).
func TestVerifyAcceptsSelfUpdateKinds(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		issued = "2026-07-18T12:00:00Z"
		expiry = "2026-07-18T12:05:00Z"
		nonce  = "AAAAAAAAAAAAAAAAAAAAAA"
		keyID  = "key-1"
	)
	cases := []struct {
		kind    string
		payload string
	}{
		{
			"agent_self_update",
			`{"release_id":"rel-1","version":"0.2.0","channel":"stable","platform":"windows/amd64",` +
				`"artifact":{"url":"https://releases.example/a.exe",` +
				`"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1024},` +
				`"min_supported_version":"0.1.0"}`,
		},
		{"agent_update_rollback", `{"reason":"0.2.0 crashes on start","confirm":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			payload := json.RawMessage(tc.payload)
			// Self-update metadata always rides command-v3, which binds the
			// signing key ID into the signed bytes.
			msg, err := canonicalCommandBytes(
				protocol.CommandEnvelopeV3, protocol.CommandSchemaV1,
				"c1", "a1", tc.kind, payload, issued, expiry, nonce, keyID,
			)
			if err != nil {
				t.Fatalf("%s must be an accepted command kind: %v", tc.kind, err)
			}
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
			if err := VerifyWithKeyID(
				pub, protocol.CommandEnvelopeV3, protocol.CommandSchemaV1,
				"c1", "a1", tc.kind, payload, issued, expiry, nonce, keyID, sig,
			); err != nil {
				t.Fatalf("Verify rejected a valid %s command: %v", tc.kind, err)
			}
			// A tampered payload must not verify under the same signature.
			tampered := json.RawMessage(`{"reason":"anything else","confirm":true}`)
			if err := VerifyWithKeyID(
				pub, protocol.CommandEnvelopeV3, protocol.CommandSchemaV1,
				"c1", "a1", tc.kind, tampered, issued, expiry, nonce, keyID, sig,
			); err == nil {
				t.Fatalf("Verify accepted a tampered %s payload", tc.kind)
			}
		})
	}
}
