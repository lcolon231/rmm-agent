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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/protocol"
)

const (
	maxCommandEnvelopeBytes = 64 * 1024
	maxCommandPayloadDepth  = 16
	maxCommandLifetime      = 24 * time.Hour
	maxIssuedAtClockSkew    = 2 * time.Minute
)

var (
	noncePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	timePattern  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z$`)
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
func canonicalCommandBytes(envelopeVersion string, schemaVersion int, commandID, agentID, kind string, payload json.RawMessage, issuedAt, expiresAt, nonce string) ([]byte, error) {
	if envelopeVersion != protocol.CommandEnvelopeV2 {
		if envelopeVersion == "" {
			return nil, fmt.Errorf("missing command envelope version")
		}
		return nil, fmt.Errorf("unsupported command envelope version %q", envelopeVersion)
	}
	if schemaVersion == 0 {
		return nil, fmt.Errorf("missing command schema version")
	}
	if schemaVersion != protocol.CommandSchemaV1 {
		return nil, fmt.Errorf("unsupported command schema version %d", schemaVersion)
	}
	if commandID == "" || agentID == "" || kind == "" {
		return nil, fmt.Errorf("malformed command envelope: command_id, agent_id, and kind are required")
	}
	switch kind {
	case "powershell", "shell", "collect_inventory":
	default:
		return nil, fmt.Errorf("unsupported command kind %q", kind)
	}
	if nonce == "" {
		return nil, fmt.Errorf("missing command nonce")
	}
	if !noncePattern.MatchString(nonce) {
		return nil, fmt.Errorf("malformed command nonce")
	}
	if _, _, err := validateCommandTimePair(issuedAt, expiresAt); err != nil {
		return nil, err
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
		"expires_at":       expiresAt,
		"issued_at":        issuedAt,
		"kind":             kind,
		"nonce":            nonce,
		"payload":          payloadVal,
		"schema_version":   schemaVersion,
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

func formatCommandTime(value time.Time) string {
	value = value.UTC()
	if value.Nanosecond() == 0 {
		return value.Format("2006-01-02T15:04:05Z")
	}
	return value.Format("2006-01-02T15:04:05.000000Z")
}

func parseCommandTime(field, raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, fmt.Errorf("missing %s", field)
	}
	if !timePattern.MatchString(raw) {
		return time.Time{}, fmt.Errorf("malformed %s: must be canonical UTC RFC3339", field)
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || formatCommandTime(parsed) != raw {
		return time.Time{}, fmt.Errorf("malformed %s: must be a valid canonical UTC timestamp", field)
	}
	return parsed.UTC(), nil
}

func validateCommandTimePair(issuedRaw, expiresRaw string) (time.Time, time.Time, error) {
	issued, err := parseCommandTime("issued_at", issuedRaw)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	expires, err := parseCommandTime("expires_at", expiresRaw)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !expires.After(issued) {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid command time window: expires_at must be later than issued_at")
	}
	if expires.Sub(issued) > maxCommandLifetime {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid command time window: lifetime exceeds %s", maxCommandLifetime)
	}
	return issued, expires, nil
}

// ValidateCommandWindow applies the signed command-v2 clock policy at receipt.
// Expiry is exclusive; issued_at tolerates a small amount of forward clock skew.
func ValidateCommandWindow(issuedRaw, expiresRaw string, now time.Time) (time.Time, error) {
	issued, expires, err := validateCommandTimePair(issuedRaw, expiresRaw)
	if err != nil {
		return time.Time{}, err
	}
	now = now.UTC()
	if issued.After(now.Add(maxIssuedAtClockSkew)) {
		return time.Time{}, fmt.Errorf("issued_at is too far in the future")
	}
	if !expires.After(now) {
		return time.Time{}, fmt.Errorf("command is expired")
	}
	return expires, nil
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
			return fmt.Errorf("floating-point payload values are not supported by command-v2")
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
func Verify(pub ed25519.PublicKey, envelopeVersion string, schemaVersion int, commandID, agentID, kind string, payload json.RawMessage, issuedAt, expiresAt, nonce, signatureB64 string) error {
	msg, err := canonicalCommandBytes(envelopeVersion, schemaVersion, commandID, agentID, kind, payload, issuedAt, expiresAt, nonce)
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
