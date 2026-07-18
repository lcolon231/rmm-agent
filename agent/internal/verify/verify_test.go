// SPDX-License-Identifier: AGPL-3.0-only
package verify

import (
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/protocol"
)

// The expected strings here are produced by Python's
// json.dumps(doc, sort_keys=True, separators=(",", ":")) — see the server's
// canonical_command_bytes. If these ever diverge, signature verification breaks.
func TestCanonicalMatchesPython(t *testing.T) {
	cases := []struct {
		name     string
		cmdID    string
		agentID  string
		kind     string
		payload  string
		expected string
	}{
		{
			name:     "simple script",
			cmdID:    "c1",
			agentID:  "a1",
			kind:     "powershell",
			payload:  `{"script":"Get-Date"}`,
			expected: `{"agent_id":"a1","command_id":"c1","envelope_version":"command-v2","expires_at":"2026-07-18T12:05:00Z","issued_at":"2026-07-18T12:00:00Z","kind":"powershell","nonce":"AAAAAAAAAAAAAAAAAAAAAA","payload":{"script":"Get-Date"},"schema_version":1}`,
		},
		{
			name:    "script with angle brackets and ampersand",
			cmdID:   "c2",
			agentID: "a2",
			kind:    "powershell",
			// Contains > and & which Go would HTML-escape by default.
			payload:  `{"script":"Get-Process | Where {$_.CPU > 5} & echo done"}`,
			expected: `{"agent_id":"a2","command_id":"c2","envelope_version":"command-v2","expires_at":"2026-07-18T12:05:00Z","issued_at":"2026-07-18T12:00:00Z","kind":"powershell","nonce":"AAAAAAAAAAAAAAAAAAAAAA","payload":{"script":"Get-Process | Where {$_.CPU > 5} & echo done"},"schema_version":1}`,
		},
		{
			name:     "empty payload",
			cmdID:    "c3",
			agentID:  "a3",
			kind:     "collect_inventory",
			payload:  ``,
			expected: `{"agent_id":"a3","command_id":"c3","envelope_version":"command-v2","expires_at":"2026-07-18T12:05:00Z","issued_at":"2026-07-18T12:00:00Z","kind":"collect_inventory","nonce":"AAAAAAAAAAAAAAAAAAAAAA","payload":{},"schema_version":1}`,
		},
		{
			name:     "nested keys sorted",
			cmdID:    "c4",
			agentID:  "a4",
			kind:     "shell",
			payload:  `{"zeta":1,"alpha":2}`,
			expected: `{"agent_id":"a4","command_id":"c4","envelope_version":"command-v2","expires_at":"2026-07-18T12:05:00Z","issued_at":"2026-07-18T12:00:00Z","kind":"shell","nonce":"AAAAAAAAAAAAAAAAAAAAAA","payload":{"alpha":2,"zeta":1},"schema_version":1}`,
		},
		{
			name:     "line separators use cross-runtime escape",
			cmdID:    "c5",
			agentID:  "a5",
			kind:     "shell",
			payload:  "{\"script\":\"before\u2028after\u2029\"}",
			expected: `{"agent_id":"a5","command_id":"c5","envelope_version":"command-v2","expires_at":"2026-07-18T12:05:00Z","issued_at":"2026-07-18T12:00:00Z","kind":"shell","nonce":"AAAAAAAAAAAAAAAAAAAAAA","payload":{"script":"before\u2028after\u2029"},"schema_version":1}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalCommandBytes(protocol.CommandEnvelopeV2, protocol.CommandSchemaV1, tc.cmdID, tc.agentID, tc.kind, []byte(tc.payload), "2026-07-18T12:00:00Z", "2026-07-18T12:05:00Z", "AAAAAAAAAAAAAAAAAAAAAA")
			if err != nil {
				t.Fatalf("canonicalCommandBytes error: %v", err)
			}
			if string(got) != tc.expected {
				t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, tc.expected)
			}
		})
	}
}

func TestValidateCommandWindowBoundaries(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	if _, err := ValidateCommandWindow("2026-07-18T12:02:00Z", "2026-07-18T12:03:00Z", now); err != nil {
		t.Fatalf("exact forward-skew boundary should pass: %v", err)
	}
	if _, err := ValidateCommandWindow("2026-07-18T12:02:00.000001Z", "2026-07-18T12:03:00Z", now); err == nil {
		t.Fatal("issued_at beyond forward-skew boundary should fail")
	}
	if _, err := ValidateCommandWindow("2026-07-18T11:59:00Z", "2026-07-18T12:00:00Z", now); err == nil {
		t.Fatal("expiry equal to now should fail")
	}
}

func TestMalformedCommandTimeFailsClosed(t *testing.T) {
	if _, _, err := validateCommandTimePair("2026-07-18T12:00:00+00:00", "2026-07-18T12:01:00Z"); err == nil {
		t.Fatal("non-canonical timezone suffix should fail")
	}
	if _, _, err := validateCommandTimePair("2026-02-30T12:00:00Z", "2026-03-01T12:00:00Z"); err == nil {
		t.Fatal("invalid calendar time should fail")
	}
}

func TestV3BindsSigningKeyID(t *testing.T) {
	got, err := canonicalCommandBytes(
		protocol.CommandEnvelopeV3, protocol.CommandSchemaV1, "c-key", "a-key",
		"shell", []byte(`{"script":"whoami"}`),
		"2026-07-18T12:00:00Z", "2026-07-18T12:05:00Z",
		"AAAAAAAAAAAAAAAAAAAAAA", "key-2026-a",
	)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_id":"a-key","command_id":"c-key","envelope_version":"command-v3","expires_at":"2026-07-18T12:05:00Z","issued_at":"2026-07-18T12:00:00Z","kind":"shell","nonce":"AAAAAAAAAAAAAAAAAAAAAA","payload":{"script":"whoami"},"schema_version":1,"signing_key_id":"key-2026-a"}`
	if string(got) != want {
		t.Fatalf("unexpected v3 canonical bytes\n got: %s\nwant: %s", got, want)
	}
	if _, err := canonicalCommandBytes(
		protocol.CommandEnvelopeV3, protocol.CommandSchemaV1, "c-key", "a-key",
		"shell", []byte(`{"script":"whoami"}`),
		"2026-07-18T12:00:00Z", "2026-07-18T12:05:00Z",
		"AAAAAAAAAAAAAAAAAAAAAA",
	); err == nil {
		t.Fatal("v3 without a signing key ID should fail closed")
	}
}
