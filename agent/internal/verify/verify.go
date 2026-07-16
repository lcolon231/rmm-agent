// Package verify checks that commands received from the server are authentic,
// i.e. signed by the server's Ed25519 private key. The canonical byte encoding
// here MUST match the server's app/core/security.canonical_command_bytes.
package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// PublicKeyFromPEM parses a PEM-encoded Ed25519 public key.
func PublicKeyFromPEM(pemStr string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}
	return edPub, nil
}

// canonicalCommandBytes reproduces the server's deterministic JSON encoding:
// sorted keys, no whitespace. Go's encoding/json sorts map keys alphabetically
// by default, which matches Python's json.dumps(sort_keys=True). The nested
// payload is emitted via json.RawMessage to preserve its exact bytes only when
// they are already canonical; to be safe we re-canonicalize by decoding into an
// interface and re-encoding.
func canonicalCommandBytes(commandID, agentID, kind string, payload json.RawMessage) ([]byte, error) {
	// Re-canonicalize the payload so key ordering/whitespace match the server.
	var payloadVal any
	if len(payload) == 0 {
		payloadVal = map[string]any{}
	} else if err := json.Unmarshal(payload, &payloadVal); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	doc := map[string]any{
		"command_id": commandID,
		"agent_id":   agentID,
		"kind":       kind,
		"payload":    payloadVal,
	}
	// json.Marshal sorts object keys; with no extra spaces this equals Python's
	// json.dumps(sort_keys=True, separators=(",", ":")).
	return marshalCanonical(doc)
}

// Verify returns nil if signatureB64 is a valid server signature over the
// command, and an error otherwise. A non-nil return means the command MUST NOT
// be executed.
func Verify(pub ed25519.PublicKey, commandID, agentID, kind string, payload json.RawMessage, signatureB64 string) error {
	msg, err := canonicalCommandBytes(commandID, agentID, kind, payload)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}
