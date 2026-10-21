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

func loadVectorFile(t *testing.T, name string) vectorFile {
	t.Helper()
	data, err := os.ReadFile("../../../contracts/test-vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func verifyV3(pub ed25519.PublicKey, tc vectorCase) error {
	e := tc.Envelope
	return VerifyWithKeyID(pub, e.EnvelopeVersion, e.SchemaVersion, e.CommandID,
		e.AgentID, e.Kind, e.Payload, e.IssuedAt, e.ExpiresAt, e.Nonce,
		e.SigningKeyID, tc.SignatureB64)
}

func v3PublicKey(t *testing.T, vectors vectorFile) ed25519.PublicKey {
	t.Helper()
	pub, err := base64.StdEncoding.DecodeString(vectors.PublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("bad public_key_b64: %v", err)
	}
	return ed25519.PublicKey(pub)
}

func TestSharedCommandV3ValidVectors(t *testing.T) {
	vectors := loadVectorFile(t, "command-v3.json")
	pub := v3PublicKey(t, vectors)
	if len(vectors.Valid) == 0 {
		t.Fatal("no v3 valid vectors")
	}
	for _, tc := range vectors.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			e := tc.Envelope
			got, err := canonicalCommandBytes(e.EnvelopeVersion, e.SchemaVersion,
				e.CommandID, e.AgentID, e.Kind, e.Payload, e.IssuedAt, e.ExpiresAt,
				e.Nonce, e.SigningKeyID)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.CanonicalJSON {
				t.Fatalf("v3 canonical mismatch\n got: %s\nwant: %s", got, tc.CanonicalJSON)
			}
			if err := verifyV3(pub, tc); err != nil {
				t.Fatalf("shared v3 vector did not verify: %v", err)
			}
		})
	}
}

// Every tampered case canonicalizes cleanly; only the signature is wrong. The
// swapped signing_key_id case proves the key ID is inside the signed bytes.
func TestSharedCommandV3TamperedVectors(t *testing.T) {
	vectors := loadVectorFile(t, "command-v3.json")
	pub := v3PublicKey(t, vectors)
	if len(vectors.Tampered) == 0 {
		t.Fatal("no v3 tampered vectors")
	}
	for _, tc := range vectors.Tampered {
		t.Run(tc.Name, func(t *testing.T) {
			err := verifyV3(pub, tc)
			if err == nil {
				t.Fatal("tampered vector verified")
			}
			if !strings.Contains(err.Error(), "signature verification failed") {
				t.Fatalf("tampered vector failed for the wrong reason: %v", err)
			}
		})
	}
}

// The agent's errors are plain strings, so each stable server code maps to the
// phrase the agent uses for the same refusal.
var v3ErrorPhrases = map[string]string{
	"missing_signing_key_id":       "signing key ID",
	"malformed_signing_key_id":     "signing key ID",
	"unsupported_version":          "unsupported command envelope version",
	"unsupported_kind":             "unsupported command kind",
	"malformed_nonce":              "malformed command nonce",
	"floating_point_not_supported": "floating-point",
}

func TestSharedCommandV3InvalidVectors(t *testing.T) {
	vectors := loadVectorFile(t, "command-v3.json")
	if len(vectors.Invalid) == 0 {
		t.Fatal("no v3 invalid vectors")
	}
	for _, tc := range vectors.Invalid {
		t.Run(tc.Name, func(t *testing.T) {
			phrase, ok := v3ErrorPhrases[tc.Error]
			if !ok {
				t.Fatalf("no agent phrase mapped for error code %q", tc.Error)
			}
			e := tc.Envelope
			_, err := canonicalCommandBytes(e.EnvelopeVersion, e.SchemaVersion,
				e.CommandID, e.AgentID, e.Kind, e.Payload, e.IssuedAt, e.ExpiresAt,
				e.Nonce, e.SigningKeyID)
			if err == nil {
				t.Fatal("invalid vector was accepted")
			}
			if !strings.Contains(err.Error(), phrase) {
				t.Fatalf("error %q does not contain %q", err, phrase)
			}
		})
	}
}

// command-v1 is retired. Its vectors carry valid v1 signatures, and the agent
// must still refuse every one of them before signature verification.
func TestCommandV1VectorsAreRefusedAsDowngrade(t *testing.T) {
	vectors := loadVectorFile(t, "command-v1.json")
	pub := v3PublicKey(t, vectors)
	if len(vectors.Valid) == 0 {
		t.Fatal("no v1 vectors")
	}
	for _, tc := range vectors.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			e := tc.Envelope
			err := Verify(pub, e.EnvelopeVersion, e.SchemaVersion, e.CommandID,
				e.AgentID, e.Kind, e.Payload, e.IssuedAt, e.ExpiresAt, e.Nonce,
				tc.SignatureB64)
			if err == nil || !strings.Contains(err.Error(), "unsupported command envelope version") {
				t.Fatalf("v1 command was not refused as a downgrade: %v", err)
			}
		})
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
	Tampered     []vectorCase `json:"tampered"`
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
