// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
)

func TestMain(m *testing.M) {
	// Production command state is ACL-restricted to SYSTEM/Administrators.
	// Unit tests run as an ordinary developer account and need to reload their
	// own temporary files; DPAPI protection is still exercised.
	applySeenStoreACL = func(string) error { return nil }
	os.Exit(m.Run())
}

func TestSeenStoreAddHas(t *testing.T) {
	s := &SeenStore{path: filepath.Join(t.TempDir(), seenFileName), entries: map[string]seenEntry{}}
	if s.Has("cmd-1") {
		t.Fatal("empty store should not contain cmd-1")
	}
	s.Add("cmd-1", time.Time{})
	if !s.Has("cmd-1") {
		t.Fatal("store should contain cmd-1 after Add")
	}
}

// TestSeenStorePersistsAcrossReload writes a store, loads a fresh instance from
// the same path, and confirms a recorded id is still present.
func TestSeenStorePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), seenFileName)
	s, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Add("cmd-persist", time.Now().Add(time.Hour).UTC())
	s.AddNonce("persisted-nonce", time.Now().Add(time.Hour).UTC())
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Has("cmd-persist") {
		t.Fatal("id should survive reload")
	}
	if !reloaded.HasNonce("persisted-nonce") {
		t.Fatal("nonce should survive reload")
	}
}

// TestSeenStorePruneDropsExpired confirms Prune removes lapsed entries while
// retaining future and no-TTL ones.
func TestSeenStorePruneDropsExpired(t *testing.T) {
	now := time.Now().UTC()
	s := &SeenStore{path: filepath.Join(t.TempDir(), seenFileName), entries: map[string]seenEntry{}}
	s.Add("expired", now.Add(-time.Minute))
	s.Add("future", now.Add(time.Minute))
	s.Add("no-ttl", time.Time{})

	if !s.Prune(now) {
		t.Fatal("prune should report removal of expired entries")
	}

	if s.Has("expired") {
		t.Error("expired entry should be pruned")
	}
	if !s.Has("future") {
		t.Error("future entry should be retained")
	}
	if !s.Has("no-ttl") {
		t.Error("no-TTL entry should be retained")
	}
}

// TestLoadSeenStoreMissingFile confirms an absent file yields an empty store,
// not an error (first run).
func TestLoadSeenStoreMissingFile(t *testing.T) {
	s, err := LoadSeenStore(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if s.Has("anything") {
		t.Fatal("fresh store should be empty")
	}
}

// TestSeenStoreSavePermissions confirms the persisted file is written 0600.
func TestSeenStoreSavePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), seenFileName)
	s, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Add("cmd", time.Time{})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// On Windows the Unix permission bits are advisory, so only assert on
	// platforms where they are meaningful.
	if perm := info.Mode().Perm(); perm != 0o600 && perm != 0o666 {
		t.Errorf("seen store perm = %o, want 0600", perm)
	}
}

func TestCommandJournalTransitionsSurviveReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), seenFileName)
	expiry := time.Now().Add(time.Hour).UTC()
	s, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveCommand("cmd-state", "nonce-state", expiry); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExecuting("cmd-state"); err != nil {
		t.Fatal(err)
	}
	want := client.CommandResult{
		ExitCode:         0,
		Stdout:           "durable",
		AgentCompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := s.StoreResult("cmd-state", expiry, want); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), want.Stdout) {
			t.Fatal("Windows command journal exposed result plaintext instead of DPAPI ciphertext")
		}
	}

	reloaded, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	pending := reloaded.PendingResults()
	if len(pending) != 1 || pending[0].CommandID != "cmd-state" ||
		pending[0].Result.Stdout != want.Stdout {
		t.Fatalf("unexpected reloaded outbox: %+v", pending)
	}
	if err := reloaded.Acknowledge("cmd-state"); err != nil {
		t.Fatal(err)
	}
	if len(reloaded.PendingResults()) != 0 {
		t.Fatal("acknowledged result must leave pending queue")
	}
	if !reloaded.Has("cmd-state") || !reloaded.HasNonce("nonce-state") {
		t.Fatal("acknowledgement must retain replay protection through expiry")
	}
}

func TestRecoverInterruptedNeverDuplicatesExecution(t *testing.T) {
	path := filepath.Join(t.TempDir(), seenFileName)
	expiry := time.Now().Add(time.Hour).UTC()
	s, err := LoadSeenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveCommand("cmd-not-started", "nonce-not-started", expiry); err != nil {
		t.Fatal(err)
	}
	if err := s.ReserveCommand("cmd-maybe-ran", "nonce-maybe-ran", expiry); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkExecuting("cmd-maybe-ran"); err != nil {
		t.Fatal(err)
	}

	released, unknown, err := s.RecoverInterrupted()
	if err != nil {
		t.Fatal(err)
	}
	if released != 1 || unknown != 1 {
		t.Fatalf("recovery counts = (%d, %d), want (1, 1)", released, unknown)
	}
	if s.Has("cmd-not-started") || s.HasNonce("nonce-not-started") {
		t.Fatal("reservation before process start should be safely releasable")
	}
	if !s.Has("cmd-maybe-ran") || !s.HasNonce("nonce-maybe-ran") {
		t.Fatal("possibly executed command must remain replay-protected")
	}
	pending := s.PendingResults()
	if len(pending) != 1 ||
		pending[0].CommandID != "cmd-maybe-ran" ||
		!strings.Contains(pending[0].Result.Stderr, "outcome is unknown") {
		t.Fatalf("unexpected interrupted result: %+v", pending)
	}
}

func TestPendingResultIsNotPrunedAfterSignedExpiry(t *testing.T) {
	now := time.Now().UTC()
	s := &SeenStore{
		path:    filepath.Join(t.TempDir(), seenFileName),
		entries: map[string]seenEntry{},
	}
	if err := s.StoreResult(
		"cmd-pending",
		now.Add(-time.Minute),
		client.CommandResult{ExitCode: 0, Stdout: "still deliver me"},
	); err != nil {
		t.Fatal(err)
	}
	if s.Prune(now) {
		t.Fatal("prune must not remove or rewrite pending results")
	}
	if len(s.PendingResults()) != 1 {
		t.Fatal("unacknowledged result must survive beyond command expiry")
	}
}

func TestUnverifiedRefusalGetsBoundedRetention(t *testing.T) {
	now := time.Now().UTC()
	s := &SeenStore{
		path:    filepath.Join(t.TempDir(), seenFileName),
		entries: map[string]seenEntry{},
	}
	if err := s.StoreResult(
		"cmd-malformed",
		time.Time{},
		client.CommandResult{ExitCode: -1, Stderr: "refused"},
	); err != nil {
		t.Fatal(err)
	}
	entry := s.entries["cmd-malformed"]
	if entry.Expiry.Before(now.Add(23*time.Hour)) ||
		entry.Expiry.After(now.Add(25*time.Hour)) {
		t.Fatalf("fallback expiry = %s, want approximately 24 hours", entry.Expiry)
	}
}
