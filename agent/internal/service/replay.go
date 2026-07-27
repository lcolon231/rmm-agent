// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/config"
)

var errResultAlreadyStored = errors.New("command result is already stored")
var applySeenStoreACL = config.ApplyLocalDataACL

// CommandExecutionState is the durable agent-side lifecycle for one accepted
// command. Every transition is saved before the corresponding side effect:
//
//	reserved -> executing -> result_pending -> acknowledged
//
// A crash in reserved is safe to retry because no process was started. A crash
// in executing is never retried because execution may have happened; recovery
// emits an explicit unknown-outcome result instead. result_pending retains the
// exact bounded result until the server idempotently acknowledges it.
type CommandExecutionState string

const (
	commandStateReserved      CommandExecutionState = "reserved"
	commandStateExecuting     CommandExecutionState = "executing"
	commandStateResultPending CommandExecutionState = "result_pending"
	commandStateAcknowledged  CommandExecutionState = "acknowledged"
)

// SeenStore is the protected, atomically persisted command journal and replay
// set. It contains accepted command IDs, signed nonces, execution state, and
// bounded results awaiting delivery. On Windows the complete file is
// DPAPI-protected and ACL-restricted because results may contain sensitive
// endpoint data.
//
// Access is expected from the single check-in goroutine, so the store is not
// safe for concurrent use and does no locking of its own.
type SeenStore struct {
	path    string
	entries map[string]seenEntry
}

// seenEntry represents either a command ID or a "nonce:" replay key. State,
// Nonce, and Result are present only on command-ID entries. Legacy stores only
// have Expiry; those entries are treated as already acknowledged.
type seenEntry struct {
	Expiry time.Time             `json:"expiry,omitempty"`
	Nonce  string                `json:"nonce,omitempty"`
	State  CommandExecutionState `json:"state,omitempty"`
	Result *client.CommandResult `json:"result,omitempty"`
}

type pendingResult struct {
	CommandID string
	Result    client.CommandResult
}

const (
	seenFileName            = "seen_commands.json"
	nonceKeyPrefix          = "nonce:"
	commandStateFileFormat  = "nodelink-agent-command-state"
	commandStateFileVersion = 1
	unverifiedResultTTL     = 24 * time.Hour
)

// SeenStorePath returns the journal path beside the config/identity files.
func SeenStorePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), seenFileName)
}

// LoadSeenStore loads either the protected command-state envelope or the
// pre-issue-113 plaintext replay map. Legacy state contains no buffered output
// and is migrated into the protected format on the next save.
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
	plain, _, err := config.UnprotectLocalData(
		data, commandStateFileFormat, commandStateFileVersion,
	)
	if err != nil {
		return nil, fmt.Errorf("unprotect seen store: %w", err)
	}
	if err := json.Unmarshal(plain, &s.entries); err != nil {
		return nil, fmt.Errorf("parse seen store: %w", err)
	}
	if s.entries == nil {
		s.entries = make(map[string]seenEntry)
	}
	return s, nil
}

// Has reports whether id has already been accepted or executed.
func (s *SeenStore) Has(id string) bool {
	_, ok := s.entries[id]
	return ok
}

// HasNonce reports whether a signed nonce has already been accepted.
func (s *SeenStore) HasNonce(nonce string) bool {
	_, ok := s.entries[nonceKeyPrefix+nonce]
	return ok
}

// Add preserves the legacy replay-set API used by migration/tests. The entry
// is considered acknowledged and has no retained result.
func (s *SeenStore) Add(id string, expiry time.Time) {
	s.entries[id] = seenEntry{Expiry: expiry, State: commandStateAcknowledged}
}

// AddNonce records a signed nonce in the replay set.
func (s *SeenStore) AddNonce(nonce string, expiry time.Time) {
	s.entries[nonceKeyPrefix+nonce] = seenEntry{Expiry: expiry}
}

// ReserveCommand atomically reserves both command ID and nonce before any
// process is allowed to start.
func (s *SeenStore) ReserveCommand(id, nonce string, expiry time.Time) error {
	if s.Has(id) {
		return fmt.Errorf("command %s is already reserved", id)
	}
	if s.HasNonce(nonce) {
		return fmt.Errorf("command nonce is already reserved")
	}
	return s.mutateAndSave(func() {
		s.entries[id] = seenEntry{
			Expiry: expiry,
			Nonce:  nonce,
			State:  commandStateReserved,
		}
		s.entries[nonceKeyPrefix+nonce] = seenEntry{Expiry: expiry}
	})
}

// MarkExecuting persists the point of no safe retry immediately before process
// creation. Recovery treats this state conservatively as outcome unknown.
func (s *SeenStore) MarkExecuting(id string) error {
	entry, ok := s.entries[id]
	if !ok || entry.State != commandStateReserved {
		return fmt.Errorf("command %s is not durably reserved", id)
	}
	return s.mutateAndSave(func() {
		entry.State = commandStateExecuting
		s.entries[id] = entry
	})
}

// StoreResult durably records the exact bounded result before any upload. It
// also supports refusal results for commands that never entered execution.
func (s *SeenStore) StoreResult(id string, expiry time.Time, result client.CommandResult) error {
	entry := s.entries[id]
	if (entry.State == commandStateAcknowledged ||
		entry.State == commandStateResultPending) && entry.Result != nil {
		return fmt.Errorf("%w for command %s", errResultAlreadyStored, id)
	}
	if entry.Expiry.IsZero() && expiry.IsZero() {
		// A refusal can happen before a signed expiry is trusted. Give those
		// acknowledged journal entries a bounded retention window rather than
		// retaining malformed command IDs forever.
		expiry = time.Now().UTC().Add(unverifiedResultTTL)
	}
	resultCopy := result
	return s.mutateAndSave(func() {
		if entry.Expiry.IsZero() {
			entry.Expiry = expiry
		}
		entry.State = commandStateResultPending
		entry.Result = &resultCopy
		s.entries[id] = entry
	})
}

// Acknowledge retains the exact result until signed expiry for replay/rollback
// recovery, but removes it from the upload queue.
func (s *SeenStore) Acknowledge(id string) error {
	entry, ok := s.entries[id]
	if !ok || entry.State != commandStateResultPending || entry.Result == nil {
		return fmt.Errorf("command %s has no pending result", id)
	}
	return s.mutateAndSave(func() {
		entry.State = commandStateAcknowledged
		s.entries[id] = entry
	})
}

// RequeueAcknowledged makes a retained result deliverable again when the
// server re-delivers a command whose prior terminal state was lost.
func (s *SeenStore) RequeueAcknowledged(id string) (bool, error) {
	entry, ok := s.entries[id]
	if !ok || entry.State != commandStateAcknowledged || entry.Result == nil {
		return false, nil
	}
	err := s.mutateAndSave(func() {
		entry.State = commandStateResultPending
		s.entries[id] = entry
	})
	return err == nil, err
}

// PendingResults returns a stable command-ID-ordered snapshot of the durable
// outbox.
func (s *SeenStore) PendingResults() []pendingResult {
	pending := make([]pendingResult, 0)
	for id, entry := range s.entries {
		if strings.HasPrefix(id, nonceKeyPrefix) ||
			entry.State != commandStateResultPending ||
			entry.Result == nil {
			continue
		}
		pending = append(pending, pendingResult{CommandID: id, Result: *entry.Result})
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].CommandID < pending[j].CommandID
	})
	return pending
}

// RecoverInterrupted resolves crash-only states without risking duplicate
// execution. reserved is removed (including its nonce) because process start
// was impossible before the executing transition. executing becomes a
// persisted failure result with an explicitly unknown outcome.
func (s *SeenStore) RecoverInterrupted() (reservedReleased, unknownQueued int, err error) {
	changed := false
	before := cloneEntries(s.entries)
	for id, entry := range s.entries {
		if strings.HasPrefix(id, nonceKeyPrefix) {
			continue
		}
		switch entry.State {
		case commandStateReserved:
			delete(s.entries, id)
			if entry.Nonce != "" {
				delete(s.entries, nonceKeyPrefix+entry.Nonce)
			}
			reservedReleased++
			changed = true
		case commandStateExecuting:
			result := client.CommandResult{
				ExitCode: -1,
				Stderr:   "agent restarted before the command result was durably recorded; execution outcome is unknown and the command was not replayed",
			}
			entry.State = commandStateResultPending
			entry.Result = &result
			s.entries[id] = entry
			unknownQueued++
			changed = true
		}
	}
	if !changed {
		return reservedReleased, unknownQueued, nil
	}
	if err := s.Save(); err != nil {
		s.entries = before
		return 0, 0, err
	}
	return reservedReleased, unknownQueued, nil
}

// Prune removes expired acknowledged/legacy entries and reports whether the
// journal changed. Work that is reserved, executing, or awaiting result
// delivery is retained past signed expiry until it can be resolved safely.
func (s *SeenStore) Prune(now time.Time) bool {
	changed := false
	for id, entry := range s.entries {
		if entry.State == commandStateReserved ||
			entry.State == commandStateExecuting ||
			entry.State == commandStateResultPending {
			continue
		}
		if !entry.Expiry.IsZero() && entry.Expiry.Before(now) {
			delete(s.entries, id)
			changed = true
		}
	}
	return changed
}

func (s *SeenStore) mutateAndSave(mutate func()) error {
	before := cloneEntries(s.entries)
	mutate()
	if err := s.Save(); err != nil {
		s.entries = before
		return err
	}
	return nil
}

func cloneEntries(entries map[string]seenEntry) map[string]seenEntry {
	clone := make(map[string]seenEntry, len(entries))
	for key, entry := range entries {
		if entry.Result != nil {
			resultCopy := *entry.Result
			entry.Result = &resultCopy
		}
		clone[key] = entry
	}
	return clone
}

// Save writes the protected journal atomically. Syncing the temporary file
// before rename ensures an acknowledged write is not merely sitting in a
// userspace buffer when execution or result upload proceeds.
func (s *SeenStore) Save() error {
	plain, err := json.Marshal(s.entries)
	if err != nil {
		return err
	}
	data, err := config.ProtectLocalData(
		commandStateFileFormat, commandStateFileVersion, plain,
	)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, seenFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp seen store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("rename seen store into place: %w", err)
	}
	if err := applySeenStoreACL(s.path); err != nil {
		return fmt.Errorf("secure seen store ACL: %w", err)
	}
	return nil
}
