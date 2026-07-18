// SPDX-License-Identifier: AGPL-3.0-only
package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type vectorEnvelope struct {
	EnvelopeVersion string          `json:"envelope_version"`
	SchemaVersion   int             `json:"schema_version"`
	CommandID       string          `json:"command_id"`
	AgentID         string          `json:"agent_id"`
	Kind            string          `json:"kind"`
	Payload         json.RawMessage `json:"payload"`
	IssuedAt        string          `json:"issued_at"`
	ExpiresAt       string          `json:"expires_at"`
	Nonce           string          `json:"nonce"`
	SigningKeyID    string          `json:"signing_key_id"`
}

func TestSharedCommandV3Vector(t *testing.T) {
	data, err := os.ReadFile("../../../contracts/test-vectors/command-v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.Valid {
		got, err := canonicalCommandBytes(
			tc.Envelope.EnvelopeVersion, tc.Envelope.SchemaVersion,
			tc.Envelope.CommandID, tc.Envelope.AgentID, tc.Envelope.Kind,
			tc.Envelope.Payload, tc.Envelope.IssuedAt, tc.Envelope.ExpiresAt,
			tc.Envelope.Nonce, tc.Envelope.SigningKeyID,
		)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.CanonicalJSON {
			t.Fatalf("v3 canonical mismatch: got %s want %s", got, tc.CanonicalJSON)
		}
	}
}

type vectorCase struct {
	Name          string         `json:"name"`
	Envelope      vectorEnvelope `json:"envelope"`
	CanonicalJSON string         `json:"canonical_json"`
	SignatureB64  string         `json:"signature_b64"`
	RawPayload    string         `json:"raw_payload"`
	Error         string         `json:"error"`
}

type vectorFile struct {
	PublicKeyB64 string       `json:"public_key_b64"`
	Valid        []vectorCase `json:"valid"`
	Invalid      []vectorCase `json:"invalid"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/test-vectors/command-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func TestSharedCommandV2ValidVectors(t *testing.T) {
	vectors := loadVectors(t)
	pub, err := base64.StdEncoding.DecodeString(vectors.PublicKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := canonicalCommandBytes(
				tc.Envelope.EnvelopeVersion,
				tc.Envelope.SchemaVersion,
				tc.Envelope.CommandID,
				tc.Envelope.AgentID,
				tc.Envelope.Kind,
				tc.Envelope.Payload,
				tc.Envelope.IssuedAt,
				tc.Envelope.ExpiresAt,
				tc.Envelope.Nonce,
			)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.CanonicalJSON {
				t.Fatalf("canonical mismatch\n got: %s\nwant: %s", got, tc.CanonicalJSON)
			}
			sig, err := base64.StdEncoding.DecodeString(tc.SignatureB64)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(ed25519.PublicKey(pub), got, sig) {
				t.Fatal("shared vector signature did not verify")
			}
		})
	}
}

func TestSharedCommandV2InvalidVectors(t *testing.T) {
	vectors := loadVectors(t)
	for _, tc := range vectors.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			payload := tc.Envelope.Payload
			if tc.RawPayload != "" {
				payload = json.RawMessage(tc.RawPayload)
			}
			_, err := canonicalCommandBytes(
				tc.Envelope.EnvelopeVersion,
				tc.Envelope.SchemaVersion,
				tc.Envelope.CommandID,
				tc.Envelope.AgentID,
				tc.Envelope.Kind,
				payload,
				tc.Envelope.IssuedAt,
				tc.Envelope.ExpiresAt,
				tc.Envelope.Nonce,
			)
			if err == nil {
				t.Fatal("invalid vector was accepted")
			}
			if tc.Error == "missing_version" && !strings.Contains(err.Error(), "missing") {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.Error == "unsupported_version" && !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
