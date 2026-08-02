// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateVersion = 1

type CheckState struct {
	PolicyRevisionID string    `json:"policy_revision_id"`
	LastEvaluated    time.Time `json:"last_evaluated"`
	Status           string    `json:"status"`
	PendingStatus    string    `json:"pending_status,omitempty"`
	PendingCount     int       `json:"pending_count,omitempty"`
}

type Store struct {
	Version int                   `json:"version"`
	Checks  map[string]CheckState `json:"checks"`
	Pending []Result              `json:"pending"`
	path    string
}

func StatePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "monitoring_state.json")
}

func LoadStore(path string) (*Store, error) {
	store := &Store{Version: stateVersion, Checks: map[string]CheckState{}, path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read monitoring state: %w", err)
	}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("decode monitoring state: %w", err)
	}
	if store.Version != stateVersion {
		return nil, fmt.Errorf("unsupported monitoring state version %d", store.Version)
	}
	if store.Checks == nil {
		store.Checks = map[string]CheckState{}
	}
	store.path = path
	return store, nil
}

func (s *Store) Save() error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode monitoring state: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create monitoring state directory: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write monitoring state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace monitoring state: %w", err)
	}
	return nil
}

func (s *Store) PendingBatch(limit int) []Result {
	if limit <= 0 || len(s.Pending) == 0 {
		return nil
	}
	if limit > len(s.Pending) {
		limit = len(s.Pending)
	}
	return append([]Result(nil), s.Pending[:limit]...)
}

func (s *Store) AcknowledgePrefix(count int) error {
	if count < 0 || count > len(s.Pending) {
		return fmt.Errorf("invalid monitoring acknowledgement count %d", count)
	}
	s.Pending = append([]Result(nil), s.Pending[count:]...)
	return s.Save()
}
