// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SeenStore is a persisted set of already-executed command IDs used for replay
// protection: a command whose ID is already present is refused rather than run a
// second time. It survives agent restarts by loading from and atomically saving
// to a small JSON file beside identity.json.
//
// Access is expected from the single check-in goroutine, so the store is not
// safe for concurrent use and does no locking of its own.
type SeenStore struct {
	path    string
	entries map[string]seenEntry
}

// seenEntry records one executed command. Expiry is retained so pruning can drop
// entries the TTL check would reject anyway; a zero Expiry means "no TTL".
type seenEntry struct {
	Expiry time.Time `json:"expiry,omitempty"`
}

// seenFileName is the file the store persists to, alongside identity.json.
const seenFileName = "seen_commands.json"

// SeenStorePath returns the store path beside the config/identity files.
func SeenStorePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), seenFileName)
}

// LoadSeenStore reads the persisted set from path, returning an empty store if
// the file does not exist yet. A corrupt/unreadable file (other than not-exist)
// is reported as an error so the caller can decide how to proceed.
func LoadSeenStore(path string) (*SeenStore, error) {
	s := &SeenStore{path: path, entries: make(map[string]seenEntry)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, fmt.Errorf("read seen store %s: %w", path, err)
	}
	if len(data) == 0 {
		return s, nil
	}
	if err := json.Unmarshal(data, &s.entries); err != nil {
		return nil, fmt.Errorf("parse seen store: %w", err)
	}
	if s.entries == nil {
		s.entries = make(map[string]seenEntry)
	}
	return s, nil
}

// Has reports whether id has already been executed.
func (s *SeenStore) Has(id string) bool {
	_, ok := s.entries[id]
	return ok
}

// Add records id (with its optional expiry) as executed. A zero expiry means the
// command carried no TTL and the entry is retained across prunes.
func (s *SeenStore) Add(id string, expiry time.Time) {
	s.entries[id] = seenEntry{Expiry: expiry}
}

// Prune drops entries whose expiry has passed relative to now; such commands
// would be caught by the TTL check anyway. Entries with no expiry are retained.
func (s *SeenStore) Prune(now time.Time) {
	for id, e := range s.entries {
		if !e.Expiry.IsZero() && e.Expiry.Before(now) {
			delete(s.entries, id)
		}
	}
}

// Save writes the store atomically (temp file + rename, 0600) so a crash mid-
// write cannot leave a truncated file.
func (s *SeenStore) Save() error {
	data, err := json.Marshal(s.entries)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, seenFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp seen store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename seen store into place: %w", err)
	}
	return nil
}
