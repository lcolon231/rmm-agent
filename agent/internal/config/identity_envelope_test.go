// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// xorProtector is a stand-in scheme so envelope logic is exercised on every
// platform without depending on DPAPI. XOR is obviously not encryption; the
// tests only need Protect(x) != x and Unprotect(Protect(x)) == x.
type xorProtector struct{}

func (xorProtector) Scheme() string { return "test-xor" }
func (xorProtector) Protect(b []byte) ([]byte, error) {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = c ^ 0x5a
	}
	return out, nil
}
func (p xorProtector) Unprotect(b []byte) ([]byte, error) { return p.Protect(b) }

func sampleIdentity() *Identity {
	return &Identity{
		AgentID:          "agent-123",
		AgentToken:       "super-secret-token",
		CommandPublicKey: "PEM",
		HeartbeatSeconds: 60,
		ServerURL:        "https://rmm.example",
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	data, err := encodeIdentity(sampleIdentity(), xorProtector{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(data, []byte("super-secret-token")) {
		t.Fatalf("protected envelope contains the plaintext token")
	}
	id, legacy, err := decodeIdentity(data, xorProtector{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if legacy {
		t.Fatalf("freshly encoded envelope reported as legacy")
	}
	if id.AgentToken != "super-secret-token" || id.AgentID != "agent-123" {
		t.Fatalf("round trip lost fields: %+v", id)
	}
}

func TestDecodeRejectsSchemeMismatch(t *testing.T) {
	data, err := encodeIdentity(sampleIdentity(), xorProtector{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// A file protected under another scheme must fail closed, never be read as
	// plaintext or passed to the wrong unprotector.
	_, _, err = decodeIdentity(data, plaintextLikeProtector{})
	if err == nil || !strings.Contains(err.Error(), "re-enroll") {
		t.Fatalf("expected scheme-mismatch failure, got %v", err)
	}
}

// plaintextLikeProtector mimics a platform that requires a different scheme.
type plaintextLikeProtector struct{}

func (plaintextLikeProtector) Scheme() string                     { return "other" }
func (plaintextLikeProtector) Protect(b []byte) ([]byte, error)   { return b, nil }
func (plaintextLikeProtector) Unprotect(b []byte) ([]byte, error) { return b, nil }

func TestDecodeRejectsUnsupportedVersion(t *testing.T) {
	env := identityEnvelope{Format: identityFormat, Version: 99, Protection: "test-xor", Data: ""}
	raw, _ := json.Marshal(env)
	_, _, err := decodeIdentity(raw, xorProtector{})
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("expected version failure, got %v", err)
	}
}

func TestDecodeRejectsCorruptEnvelope(t *testing.T) {
	env := identityEnvelope{Format: identityFormat, Version: 1, Protection: "test-xor", Data: "!!not-base64!!"}
	raw, _ := json.Marshal(env)
	if _, _, err := decodeIdentity(raw, xorProtector{}); err == nil {
		t.Fatalf("expected corruption failure")
	}

	// Valid base64 but garbage payload after unprotect.
	env.Data = "aGVsbG8="
	raw, _ = json.Marshal(env)
	if _, _, err := decodeIdentity(raw, xorProtector{}); err == nil {
		t.Fatalf("expected payload corruption failure")
	}
}

func TestValidateIdentityEnvelopeWithoutDecrypting(t *testing.T) {
	data, err := encodeIdentity(sampleIdentity(), xorProtector{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := validateIdentityEnvelope(data, "test-xor"); err != nil {
		t.Fatalf("validate: %v", err)
	}

	var env identityEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*identityEnvelope){
		"wrong format":     func(e *identityEnvelope) { e.Format = "other" },
		"wrong version":    func(e *identityEnvelope) { e.Version = 99 },
		"wrong protection": func(e *identityEnvelope) { e.Protection = "other" },
		"empty data":       func(e *identityEnvelope) { e.Data = "" },
		"invalid base64":   func(e *identityEnvelope) { e.Data = "not-base64!!" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := env
			mutate(&candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateIdentityEnvelope(raw, "test-xor"); err == nil {
				t.Fatalf("%s unexpectedly accepted", name)
			}
		})
	}
	if err := validateIdentityEnvelope([]byte(`{"not":"json"`), "test-xor"); err == nil {
		t.Fatal("malformed JSON unexpectedly accepted")
	}
}

func TestValidateTokenFreeUpgradeState(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	if err := SaveInstallConfig(configPath, "https://rmm.example"); err != nil {
		t.Fatal(err)
	}
	if err := sampleIdentity().Save(IdentityPath(configPath)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTokenFreeUpgradeState(configPath); err != nil {
		t.Fatalf("valid upgrade state rejected: %v", err)
	}

	tokenConfig := []byte(`{"server_url":"https://rmm.example","enrollment_token":""}`)
	if err := os.WriteFile(configPath, tokenConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTokenFreeUpgradeState(configPath); err == nil ||
		!strings.Contains(err.Error(), "enrollment_token") {
		t.Fatalf("token-bearing config was not rejected: %v", err)
	}
}

func TestDecodeLegacyPlaintext(t *testing.T) {
	raw, _ := json.Marshal(sampleIdentity())
	id, legacy, err := decodeIdentity(raw, xorProtector{})
	if err != nil {
		t.Fatalf("decode legacy: %v", err)
	}
	if !legacy {
		t.Fatalf("legacy plaintext not reported as legacy")
	}
	if id.AgentToken != "super-secret-token" {
		t.Fatalf("legacy decode lost fields: %+v", id)
	}
}

func TestDecodeRejectsUnrecognizedJSON(t *testing.T) {
	if _, _, err := decodeIdentity([]byte(`{"hello":"world"}`), xorProtector{}); err == nil {
		t.Fatalf("expected unrecognized-format failure")
	}
	if _, _, err := decodeIdentity([]byte(`not json at all`), xorProtector{}); err == nil {
		t.Fatalf("expected parse failure")
	}
}

// TestLoadIdentityMigratesLegacyFile exercises the real platform protector:
// a pre-envelope plaintext identity.json is rewritten in envelope form on
// first load and loads identically afterwards.
func TestLoadIdentityMigratesLegacyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	raw, _ := json.MarshalIndent(sampleIdentity(), "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	id, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("load legacy: %v", err)
	}
	if id.AgentToken != "super-secret-token" {
		t.Fatalf("migration lost fields: %+v", id)
	}

	// The file must now be in envelope form, declaring this platform's scheme.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env identityEnvelope
	if err := json.Unmarshal(data, &env); err != nil || env.Format != identityFormat {
		t.Fatalf("migrated file is not an identity envelope: %s", data)
	}
	if env.Protection != platformProtector.Scheme() {
		t.Fatalf("migrated envelope scheme %q != platform scheme %q", env.Protection, platformProtector.Scheme())
	}
	if runtime.GOOS == "windows" && bytes.Contains(data, []byte("super-secret-token")) {
		t.Fatalf("migrated Windows identity still contains plaintext token")
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary write file left behind")
	}

	// And it loads again through the normal (non-legacy) path.
	id2, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("reload migrated identity: %v", err)
	}
	if id2.AgentID != id.AgentID || id2.AgentToken != id.AgentToken {
		t.Fatalf("reload mismatch: %+v vs %+v", id2, id)
	}
}

func TestSaveThenLoadWithPlatformProtector(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := sampleIdentity().Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	id, err := LoadIdentity(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if id.AgentToken != "super-secret-token" {
		t.Fatalf("round trip lost fields: %+v", id)
	}
}

func TestLoadIdentityMissingFileIsNotExist(t *testing.T) {
	_, err := LoadIdentity(filepath.Join(t.TempDir(), "absent.json"))
	if !os.IsNotExist(err) {
		t.Fatalf("missing identity must surface os.IsNotExist, got %v", err)
	}
}
