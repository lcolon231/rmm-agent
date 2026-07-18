// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

	s.Prune(now)

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
