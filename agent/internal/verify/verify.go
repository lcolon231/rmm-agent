// SPDX-License-Identifier: AGPL-3.0-only
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
	"io"
	"strconv"
	"strings"

	"github.com/lcolon231/rmm/agent/internal/protocol"
)

const (
	maxCommandEnvelopeBytes = 64 * 1024
	maxCommandPayloadDepth  = 16
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
func canonicalCommandBytes(envelopeVersion, commandID, agentID, kind string, payload json.RawMessage) ([]byte, error) {
	if envelopeVersion != protocol.CommandEnvelopeV1 {
		if envelopeVersion == "" {
			return nil, fmt.Errorf("missing command envelope version")
		}
		return nil, fmt.Errorf("unsupported command envelope version %q", envelopeVersion)
	}
	if commandID == "" || agentID == "" || kind == "" {
		return nil, fmt.Errorf("malformed command envelope: command_id, agent_id, and kind are required")
	}
	switch kind {
	case "powershell", "shell", "collect_inventory":
	default:
		return nil, fmt.Errorf("unsupported command kind %q", kind)
	}

	// Re-canonicalize the payload so key ordering/whitespace match the server.
	var payloadVal any
	if len(payload) == 0 {
		payloadVal = map[string]any{}
	} else {
		dec := json.NewDecoder(strings.NewReader(string(payload)))
		dec.UseNumber()
		if err := dec.Decode(&payloadVal); err != nil {
			return nil, fmt.Errorf("decode payload: %w", err)
		}
		if err := ensureJSONEOF(dec); err != nil {
			return nil, fmt.Errorf("decode payload: %w", err)
		}
	}
	if _, ok := payloadVal.(map[string]any); !ok {
		return nil, fmt.Errorf("malformed command envelope: payload must be a JSON object")
	}
	if err := validatePayloadValue(payloadVal, 0); err != nil {
		return nil, err
	}

	doc := map[string]any{
		"agent_id":         agentID,
		"command_id":       commandID,
		"envelope_version": envelopeVersion,
		"kind":             kind,
		"payload":          payloadVal,
	}
	// json.Marshal sorts object keys; with no extra spaces this equals Python's
	// json.dumps(sort_keys=True, separators=(",", ":")).
	encoded, err := marshalCanonical(doc)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxCommandEnvelopeBytes {
		return nil, fmt.Errorf("canonical command envelope exceeds %d bytes", maxCommandEnvelopeBytes)
	}
	return encoded, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func validatePayloadValue(value any, depth int) error {
	if depth > maxCommandPayloadDepth {
		return fmt.Errorf("payload nesting exceeds %d levels", maxCommandPayloadDepth)
	}
	switch v := value.(type) {
	case nil, string, bool:
		return nil
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return fmt.Errorf("floating-point payload values are not supported by command-v1")
		}
		if _, err := strconv.ParseInt(string(v), 10, 64); err != nil {
			return fmt.Errorf("payload integers must fit signed 64-bit")
		}
		return nil
	case []any:
		for _, item := range v {
			if err := validatePayloadValue(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, item := range v {
			if err := validatePayloadValue(item, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported payload value %T", value)
	}
}

// Verify returns nil if signatureB64 is a valid server signature over the
// command, and an error otherwise. A non-nil return means the command MUST NOT
// be executed.
func Verify(pub ed25519.PublicKey, envelopeVersion, commandID, agentID, kind string, payload json.RawMessage, signatureB64 string) error {
	msg, err := canonicalCommandBytes(envelopeVersion, commandID, agentID, kind, payload)
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
