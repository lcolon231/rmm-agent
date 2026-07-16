package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtractScript(t *testing.T) {
	cases := map[string]string{
		`{"script":"whoami"}`:       "whoami",
		`{"script":"","other":1}`:   "",
		`{}`:                        "",
		`{"not_script":"x"}`:        "",
		`{"script":"line1\nline2"}`: "line1\nline2",
	}
	for payload, want := range cases {
		if got := extractScript(json.RawMessage(payload)); got != want {
			t.Errorf("extractScript(%s) = %q, want %q", payload, got, want)
		}
	}
}

func TestLoadSessionFatalOnMissingConfig(t *testing.T) {
	dir := t.TempDir()
	a := NewAgent(filepath.Join(dir, "does-not-exist.json"), "test", log.New(&bytes.Buffer{}, "", 0))

	_, err := a.loadSession()
	if err == nil {
		t.Fatal("expected error for missing config")
	}
	if !isFatal(err) {
		t.Fatalf("missing config should be fatal, got %v", err)
	}
}

func TestLoadSessionFatalWhenNoCredentials(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	// Valid config but no enrollment token and no identity on disk.
	if err := os.WriteFile(cfg, []byte(`{"server_url":"https://example.invalid"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NewAgent(cfg, "test", log.New(&bytes.Buffer{}, "", 0))

	_, err := a.loadSession()
	if err == nil || !isFatal(err) {
		t.Fatalf("expected fatal error, got %v", err)
	}
}

// TestRunRetriesWhenServerUnreachable exercises the network-resilience path: an
// enrolled agent whose server is down must back off and keep retrying quietly
// rather than crash or spin, and must stop cleanly when ctx is cancelled.
func TestRunRetriesWhenServerUnreachable(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	// 127.0.0.1:1 refuses connections immediately.
	unreachable := "http://127.0.0.1:1"
	if err := os.WriteFile(cfg, []byte(`{"server_url":"`+unreachable+`","heartbeat_seconds":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFakeIdentity(t, filepath.Join(dir, "identity.json"), unreachable)

	var buf bytes.Buffer
	a := NewAgent(cfg, "test", log.New(&buf, "", 0))
	// Tight timings so several retries happen inside the test window.
	a.backoffInitial = 10 * time.Millisecond
	a.backoffMax = 40 * time.Millisecond
	a.shutdownGrace = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error, want nil on ctx cancel: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after context cancellation (possible hang)")
	}

	if !strings.Contains(buf.String(), "check-in failed") {
		t.Fatalf("expected a 'check-in failed' retry log, got:\n%s", buf.String())
	}
}

// writeFakeIdentity writes an identity.json with a real (parseable) Ed25519
// public key so loadSession does not treat it as a fatal key-parse error.
func writeFakeIdentity(t *testing.T, path, serverURL string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	id := map[string]any{
		"agent_id":           "agent-test",
		"agent_token":        "token-test",
		"command_public_key": pemStr,
		"heartbeat_seconds":  1,
		"server_url":         serverURL,
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
