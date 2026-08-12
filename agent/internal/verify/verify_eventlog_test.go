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

// TestVerifyAcceptsQueryEventLog is a regression guard for issue #58: the agent
// signature-verification kind allowlist (in canonicalCommandBytes) omitted
// query_event_log, so every server-signed event log command was refused before
// its signature was even checked ("unsupported command kind"). No test exercised
// a query_event_log envelope through Verify, so the gap shipped silently. This
// signs a valid query_event_log command and asserts Verify accepts it.
func TestVerifyAcceptsQueryEventLog(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		issued = "2026-07-18T12:00:00Z"
		expiry = "2026-07-18T12:05:00Z"
		nonce  = "AAAAAAAAAAAAAAAAAAAAAA"
	)
	payload := json.RawMessage(`{"channel":"Security","tier_ack":true,"time_window_seconds":3600,"max_events":100}`)

	msg, err := canonicalCommandBytes(
		protocol.CommandEnvelopeV2, protocol.CommandSchemaV1,
		"c1", "a1", "query_event_log", payload, issued, expiry, nonce,
	)
	if err != nil {
		t.Fatalf("query_event_log must be an accepted command kind: %v", err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
	if err := Verify(
		pub, protocol.CommandEnvelopeV2, protocol.CommandSchemaV1,
		"c1", "a1", "query_event_log", payload, issued, expiry, nonce, sig,
	); err != nil {
		t.Fatalf("Verify rejected a valid query_event_log command: %v", err)
	}
}
