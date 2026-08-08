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
	"github.com/lcolon231/rmm/agent/internal/config"
	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/protocol"
	"github.com/lcolon231/rmm/agent/internal/telemetry"
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
	posts    map[string]int
	executed map[string]bool
}

// newTestSession builds a session whose api points at an httptest server that
// records reported results, and whose executor is a stub. It returns the agent,
// session, the server's signing key, and the capture so tests can assert on
// refusal/execution behavior.
func newTestSession(t *testing.T) (*Agent, *session, ed25519.PrivateKey, *resultCapture) {
	t.Helper()
	cap := &resultCapture{
		results:  map[string]client.CommandResult{},
		posts:    map[string]int{},
		executed: map[string]bool{},
	}

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
		cap.posts[id]++
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
// canonical command-v2 bytes, mirroring the server's
// encoding (sorted keys, no whitespace, no HTML escaping).
func signCommand(t *testing.T, priv ed25519.PrivateKey, agentID string, cmd *client.Command) {
	t.Helper()
	if cmd.EnvelopeVersion == "" {
		cmd.EnvelopeVersion = protocol.CommandEnvelopeV2
	}
	if cmd.SchemaVersion == 0 {
		cmd.SchemaVersion = protocol.CommandSchemaV1
	}
	if cmd.IssuedAt == "" {
		cmd.IssuedAt = time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05.000000Z")
	}
	if cmd.ExpiresAt == "" {
		cmd.ExpiresAt = time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05.000000Z")
	}
	if cmd.Nonce == "" {
		cmd.Nonce = "AAAAAAAAAAAAAAAAAAAAAA"
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
		"expires_at":       cmd.ExpiresAt,
		"issued_at":        cmd.IssuedAt,
		"kind":             cmd.Kind,
		"nonce":            cmd.Nonce,
		"payload":          payloadVal,
		"schema_version":   cmd.SchemaVersion,
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
		ExpiresAt: time.Now().Add(-time.Minute).UTC().Format("2006-01-02T15:04:05.000000Z"),
		IssuedAt:  time.Now().Add(-time.Hour).UTC().Format("2006-01-02T15:04:05.000000Z"),
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
	if res.ExitCode != -1 || !strings.Contains(res.Stderr, "invalid signed time window") {
		t.Fatalf("unexpected refusal result: %+v", res)
	}
	if !s.seen.Has(cmd.ID) {
		t.Fatal("refusal result should be retained for idempotent delivery")
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
	if !ok || res.ExitCode != -1 || !strings.Contains(res.Stderr, "signature verification failed") {
		t.Fatalf("unparseable expiry should fail closed, got %+v (reported=%v)", res, ok)
	}
}

func TestProcessCommandStrippedExpiryIsRefused(t *testing.T) {
	a, s, priv, cap := newTestSession(t)
	cmd := client.Command{
		ID:      "cmd-no-ttl",
		AgentID: s.agentID,
		Kind:    "shell",
		Payload: json.RawMessage(`{"script":"echo run"}`),
	}
	signCommand(t, priv, s.agentID, &cmd)
	cmd.ExpiresAt = "" // Simulate transport stripping after signing.

	a.processCommand(context.Background(), s, cmd)

	if cap.executed["echo run"] {
		t.Fatal("command with stripped expiry must not execute")
	}
	if !s.seen.Has(cmd.ID) {
		t.Fatal("refusal result should be retained in the durable outbox")
	}
	if res, ok := cap.results[cmd.ID]; !ok || res.ExitCode != -1 {
		t.Fatalf("expected a refusal result, got %+v (reported=%v)", res, ok)
	}
}

func TestProcessCommandRepeatedNonceIsRefused(t *testing.T) {
	a, s, priv, cap := newTestSession(t)
	first := client.Command{ID: "cmd-nonce-1", AgentID: s.agentID, Kind: "shell", Payload: json.RawMessage(`{"script":"first"}`), Nonce: "BBBBBBBBBBBBBBBBBBBBBB"}
	signCommand(t, priv, s.agentID, &first)
	a.processCommand(context.Background(), s, first)
	if !s.seen.HasNonce(first.Nonce) {
		t.Fatal("accepted nonce should be persisted in replay state")
	}

	second := client.Command{ID: "cmd-nonce-2", AgentID: s.agentID, Kind: "shell", Payload: json.RawMessage(`{"script":"second"}`), Nonce: first.Nonce}
	signCommand(t, priv, s.agentID, &second)
	a.processCommand(context.Background(), s, second)
	if cap.executed["second"] {
		t.Fatal("a repeated nonce must not execute")
	}
	if res, ok := cap.results[second.ID]; !ok || !strings.Contains(res.Stderr, "repeated nonce") {
		t.Fatalf("expected repeated nonce refusal, got %+v (reported=%v)", res, ok)
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
	if res, ok := cap.results[cmd.ID]; !ok || res.Stdout != "ok" {
		t.Fatalf("replayed command should re-report the exact retained result, got %+v", res)
	}
	if cap.posts[cmd.ID] != 2 {
		t.Fatalf("expected original plus idempotent retry, got %d posts", cap.posts[cmd.ID])
	}
}

func TestPendingResultRetriesAfterOutageAndRestart(t *testing.T) {
	var (
		mu       sync.Mutex
		attempts int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		current := attempts
		mu.Unlock()
		if current == 1 {
			http.Error(w, "temporary outage", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	path := filepath.Join(t.TempDir(), seenFileName)
	store, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	result := client.CommandResult{
		ExitCode:         0,
		Stdout:           "completed once",
		AgentCompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := store.StoreResult("cmd-outbox", time.Now().Add(time.Hour), result); err != nil {
		t.Fatal(err)
	}
	a := &Agent{log: log.New(&bytes.Buffer{}, "", 0)}
	s := &session{api: client.New(srv.URL, "token"), seen: store}
	if err := a.flushPendingResults(context.Background(), s); err == nil {
		t.Fatal("first upload should fail")
	}
	if len(store.PendingResults()) != 1 {
		t.Fatal("failed upload must remain pending")
	}

	reloaded, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted := &session{api: client.New(srv.URL, "token"), seen: reloaded}
	if err := a.flushPendingResults(context.Background(), restarted); err != nil {
		t.Fatalf("retry after restart: %v", err)
	}
	if len(reloaded.PendingResults()) != 0 {
		t.Fatal("acknowledged retry should leave the upload queue")
	}
	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 {
		t.Fatalf("result delivery attempts = %d, want 2", attempts)
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

// TestCheckInQuarantineSuspendsExecution: a quarantined ack must execute
// nothing — even if commands are present in it — and the transition must be
// logged once, not on every beat, then cleared when the server restores trust.
func TestCheckInQuarantineSuspendsExecution(t *testing.T) {
	var (
		mu         sync.Mutex
		trustState = "quarantined"
		resultPost = false
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/result") {
			mu.Lock()
			resultPost = true
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mu.Lock()
		state := trustState
		mu.Unlock()
		// A malicious/buggy server state could still include commands in a
		// quarantined ack; the agent must ignore them.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          true,
			"trust_state": state,
			"pending_commands": []map[string]any{{
				"id": "cmd-q", "agent_id": "agent-1", "kind": "shell",
				"payload": map[string]any{"script": "echo pwned"}, "signature": "x",
			}},
		})
	}))
	t.Cleanup(srv.Close)

	executed := false
	var buf bytes.Buffer
	a := &Agent{
		log: log.New(&buf, "", 0),
		run: func(ctx context.Context, kind, script string) executor.Result {
			executed = true
			return executor.Result{}
		},
	}
	seen, err := LoadSeenStore(filepath.Join(t.TempDir(), seenFileName))
	if err != nil {
		t.Fatal(err)
	}
	s := &session{api: client.New(srv.URL, "tok"), agentID: "agent-1", seen: seen}

	for i := 0; i < 2; i++ { // two beats: the transition must be logged once
		if err := a.checkIn(context.Background(), context.Background(), s); err != nil {
			t.Fatalf("checkIn while quarantined: %v", err)
		}
	}
	if executed {
		t.Fatal("quarantined agent executed a command")
	}
	if resultPost {
		t.Fatal("quarantined agent reported a result")
	}
	if got := strings.Count(buf.String(), "QUARANTINED"); got != 1 {
		t.Fatalf("expected exactly one quarantine log line, got %d:\n%s", got, buf.String())
	}
	if !s.quarantined {
		t.Fatal("session did not record quarantine state")
	}

	mu.Lock()
	trustState = "active"
	mu.Unlock()
	// Restored: the beat still refuses the unsigned command above (signature
	// verification), but the quarantine flag must clear and be logged.
	if err := a.checkIn(context.Background(), context.Background(), s); err != nil {
		t.Fatalf("checkIn after restore: %v", err)
	}
	if s.quarantined {
		t.Fatal("session did not clear quarantine state after restore")
	}
	if !strings.Contains(buf.String(), "restored") {
		t.Fatalf("expected a restore log line:\n%s", buf.String())
	}
	if executed {
		t.Fatal("unsigned command executed after restore")
	}
}

// TestUnauthorizedIsTyped: a 401 from the server must be recognizable so the
// runtime can log the may-be-revoked hint instead of a generic failure.
func TestUnauthorizedIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	api := client.New(srv.URL, "revoked-token")
	_, err := api.Heartbeat(context.Background(), telemetry.Sample{}, nil)
	if err == nil {
		t.Fatal("expected error from 401 heartbeat")
	}
	if !client.IsUnauthorized(err) {
		t.Fatalf("401 not detected as unauthorized: %v", err)
	}
}

// --------------------------------------------------------------------------- #
// Credential renewal (issue #125)
// --------------------------------------------------------------------------- #

func TestCredentialRenewDue(t *testing.T) {
	now := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	rfc := func(tm time.Time) string { return tm.Format(time.RFC3339Nano) }
	cases := []struct {
		name     string
		expires  string
		obtained string
		want     bool
	}{
		{"no expiry is never due", "", rfc(now.Add(-time.Hour)), false},
		{"before midpoint not due", rfc(now.Add(time.Hour)), rfc(now.Add(-30 * time.Minute)), false},
		{"past midpoint due", rfc(now.Add(30 * time.Minute)), rfc(now.Add(-90 * time.Minute)), true},
		{"unparseable expiry not due", "not-a-time", rfc(now.Add(-time.Hour)), false},
		{"missing obtained but still valid is due", rfc(now.Add(time.Hour)), "", true},
		{"missing obtained and expired not due", rfc(now.Add(-time.Minute)), "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := &config.Identity{CredentialExpiresAt: tc.expires, CredentialObtainedAt: tc.obtained}
			if got := credentialRenewDue(id, now); got != tc.want {
				t.Fatalf("credentialRenewDue = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMaybeRenewCredentialRotatesAndPersists(t *testing.T) {
	var renewCalls int
	var gotNonce, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/agents/credentials/renew") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		renewCalls++
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			RotationNonce string `json:"rotation_nonce"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotNonce = body.RotationNonce
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id":              "agent-1",
			"agent_token":           "new-token-xyz",
			"credential_expires_at": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
			"overlap_expires_at":    time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339Nano),
			"credential_generation": 2,
		})
	}))
	defer srv.Close()

	idPath := filepath.Join(t.TempDir(), "identity.json")
	id := &config.Identity{
		AgentID:              "agent-1",
		AgentToken:           "old-token",
		CredentialExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		CredentialObtainedAt: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
		ServerURL:            srv.URL,
	}
	a := &Agent{log: log.New(&bytes.Buffer{}, "", 0)}
	s := &session{api: client.New(srv.URL, "old-token"), identity: id, identityPath: idPath, agentID: "agent-1"}

	if err := a.maybeRenewCredential(context.Background(), s); err != nil {
		t.Fatalf("maybeRenewCredential: %v", err)
	}
	if renewCalls != 1 {
		t.Fatalf("want exactly 1 renewal call, got %d", renewCalls)
	}
	if gotAuth != "Bearer old-token" {
		t.Fatalf("renewal must present the current credential, got %q", gotAuth)
	}
	if len(gotNonce) < 16 {
		t.Fatalf("rotation nonce too short: %q", gotNonce)
	}
	if s.identity.AgentToken != "new-token-xyz" {
		t.Fatalf("token not rotated in identity: %q", s.identity.AgentToken)
	}
	// The client adopted the new token, so a subsequent authed call carries it.
	if _, err := s.api.RenewCredential(context.Background(), "second-nonce-000001"); err != nil {
		t.Fatalf("second renew: %v", err)
	}
	if gotAuth != "Bearer new-token-xyz" {
		t.Fatalf("client did not adopt rotated token, sent %q", gotAuth)
	}
}

func TestMaybeRenewCredentialNotDueMakesNoCall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	id := &config.Identity{
		AgentID:              "agent-1",
		AgentToken:           "tok",
		CredentialExpiresAt:  time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		CredentialObtainedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	a := &Agent{log: log.New(&bytes.Buffer{}, "", 0)}
	s := &session{api: client.New(srv.URL, "tok"), identity: id, agentID: "agent-1"}
	if err := a.maybeRenewCredential(context.Background(), s); err != nil {
		t.Fatalf("maybeRenewCredential: %v", err)
	}
	if calls != 0 {
		t.Fatalf("credential not yet due, expected no renewal call, got %d", calls)
	}
}

func TestMaybeRenewCredentialRevokedIsSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	id := &config.Identity{
		AgentID:              "agent-1",
		AgentToken:           "revoked-tok",
		CredentialExpiresAt:  time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
		CredentialObtainedAt: time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339Nano),
	}
	a := &Agent{log: log.New(&bytes.Buffer{}, "", 0)}
	s := &session{api: client.New(srv.URL, "revoked-tok"), identity: id, agentID: "agent-1"}
	err := a.maybeRenewCredential(context.Background(), s)
	if !client.IsUnauthorized(err) {
		t.Fatalf("a revoked identity must surface an unauthorized error, got %v", err)
	}
	if s.identity.AgentToken != "revoked-tok" {
		t.Fatalf("token must not change on a rejected renewal, got %q", s.identity.AgentToken)
	}
}
