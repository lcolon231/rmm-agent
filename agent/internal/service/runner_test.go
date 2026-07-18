// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/protocol"
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

	_, err := a.loadSession(context.Background())
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

	_, err := a.loadSession(context.Background())
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

// resultCapture records the CommandResults the agent reports back, keyed by
// command id, along with whether the stub executor was invoked.
type resultCapture struct {
	mu       sync.Mutex
	results  map[string]client.CommandResult
	executed map[string]bool
}

// newTestSession builds a session whose api points at an httptest server that
// records reported results, and whose executor is a stub. It returns the agent,
// session, the server's signing key, and the capture so tests can assert on
// refusal/execution behavior.
func newTestSession(t *testing.T) (*Agent, *session, ed25519.PrivateKey, *resultCapture) {
	t.Helper()
	cap := &resultCapture{results: map[string]client.CommandResult{}, executed: map[string]bool{}}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path is /api/v1/commands/{id}/result.
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		id := ""
		if len(parts) >= 4 {
			id = parts[3]
		}
		var res client.CommandResult
		_ = json.NewDecoder(r.Body).Decode(&res)
		cap.mu.Lock()
		cap.results[id] = res
		cap.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seen, err := LoadSeenStore(filepath.Join(t.TempDir(), seenFileName))
	if err != nil {
		t.Fatal(err)
	}

	a := &Agent{
		log: log.New(&bytes.Buffer{}, "", 0),
		run: func(ctx context.Context, kind, script string) executor.Result {
			cap.mu.Lock()
			cap.executed[script] = true
			cap.mu.Unlock()
			return executor.Result{ExitCode: 0, Stdout: "ok"}
		},
	}
	s := &session{
		api:     client.New(srv.URL, "test-token"),
		pub:     pub,
		agentID: "agent-1",
		seen:    seen,
	}
	return a, s, priv, cap
}

// signCommand fills cmd.Signature with a valid server signature over the
// canonical {command_id, agent_id, kind, payload} bytes, mirroring the server's
// encoding (sorted keys, no whitespace, no HTML escaping).
func signCommand(t *testing.T, priv ed25519.PrivateKey, agentID string, cmd *client.Command) {
	t.Helper()
	if cmd.EnvelopeVersion == "" {
		cmd.EnvelopeVersion = protocol.CommandEnvelopeV1
	}
	var payloadVal any
	if len(cmd.Payload) == 0 {
		payloadVal = map[string]any{}
	} else if err := json.Unmarshal(cmd.Payload, &payloadVal); err != nil {
		t.Fatal(err)
	}
	doc := map[string]any{
		"agent_id":         agentID,
		"command_id":       cmd.ID,
		"envelope_version": cmd.EnvelopeVersion,
		"kind":             cmd.Kind,
		"payload":          payloadVal,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		t.Fatal(err)
	}
	msg := bytes.TrimRight(buf.Bytes(), "\n")
	sig := ed25519.Sign(priv, msg)
	cmd.Signature = base64.StdEncoding.EncodeToString(sig)
}

func TestProcessCommandExpiredIsRefused(t *testing.T) {
	a, s, priv, cap := newTestSession(t)
	cmd := client.Command{
		ID:        "cmd-expired",
		AgentID:   s.agentID,
		Kind:      "shell",
		Payload:   json.RawMessage(`{"script":"echo hi"}`),
		ExpiresAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano),
	}
	signCommand(t, priv, s.agentID, &cmd)

	a.processCommand(context.Background(), s, cmd)

	if cap.executed["echo hi"] {
		t.Fatal("expired command must not execute")
	}
	res, ok := cap.results[cmd.ID]
	if !ok {
		t.Fatal("expired command should report a failure result")
	}
	if res.ExitCode != -1 || !strings.Contains(res.Stderr, "past TTL") {
		t.Fatalf("unexpected refusal result: %+v", res)
	}
	if s.seen.Has(cmd.ID) {
		t.Fatal("refused command must not be recorded as executed")
	}
}

func TestProcessCommandUnparseableExpiryFailsClosed(t *testing.T) {
	a, s, priv, cap := newTestSession(t)
	cmd := client.Command{
		ID:        "cmd-bad-ttl",
		AgentID:   s.agentID,
		Kind:      "shell",
		Payload:   json.RawMessage(`{"script":"echo hi"}`),
		ExpiresAt: "not-a-timestamp",
	}
	signCommand(t, priv, s.agentID, &cmd)

	a.processCommand(context.Background(), s, cmd)

	if cap.executed["echo hi"] {
		t.Fatal("command with unparseable expiry must not execute")
	}
	res, ok := cap.results[cmd.ID]
	if !ok || res.ExitCode != -1 || !strings.Contains(res.Stderr, "past TTL") {
		t.Fatalf("unparseable expiry should fail closed, got %+v (reported=%v)", res, ok)
	}
}

func TestProcessCommandEmptyExpiryExecutes(t *testing.T) {
	a, s, priv, cap := newTestSession(t)
	cmd := client.Command{
		ID:      "cmd-no-ttl",
		AgentID: s.agentID,
		Kind:    "shell",
		Payload: json.RawMessage(`{"script":"echo run"}`),
		// ExpiresAt intentionally empty: no TTL.
	}
	signCommand(t, priv, s.agentID, &cmd)

	a.processCommand(context.Background(), s, cmd)

	if !cap.executed["echo run"] {
		t.Fatal("command with empty expiry should execute")
	}
	if !s.seen.Has(cmd.ID) {
		t.Fatal("executed command should be recorded in the replay store")
	}
	if res, ok := cap.results[cmd.ID]; !ok || res.ExitCode != 0 {
		t.Fatalf("expected a success result, got %+v (reported=%v)", res, ok)
	}
}

func TestProcessCommandReplayIsRefused(t *testing.T) {
	a, s, priv, cap := newTestSession(t)
	cmd := client.Command{
		ID:      "cmd-replay",
		AgentID: s.agentID,
		Kind:    "shell",
		Payload: json.RawMessage(`{"script":"echo once"}`),
	}
	signCommand(t, priv, s.agentID, &cmd)

	// First execution succeeds and records the id.
	a.processCommand(context.Background(), s, cmd)
	if !s.seen.Has(cmd.ID) {
		t.Fatal("first execution should record the id")
	}

	// Reset capture state and re-present the same command.
	cap.mu.Lock()
	cap.executed = map[string]bool{}
	delete(cap.results, cmd.ID)
	cap.mu.Unlock()

	a.processCommand(context.Background(), s, cmd)

	if cap.executed["echo once"] {
		t.Fatal("replayed command must not execute a second time")
	}
	if _, ok := cap.results[cmd.ID]; ok {
		t.Fatal("replayed command must not report a result (would clobber the original)")
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
