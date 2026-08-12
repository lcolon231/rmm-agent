// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Journal states. The journal is the only durable record that survives the
// binary swap and the restart, so every transition is written and fsynced
// before the action it authorizes.
const (
	// StateStaged: the artifact is verified and staged, nothing replaced yet.
	StateStaged = "staged"
	// StateInstalled: the running binary was replaced and a restart requested.
	// A start observed in this state owes a health check.
	StateInstalled = "installed"
	// StateCommitted: the new build passed its health check.
	StateCommitted = "committed"
	// StateRolledBack: the previous build was restored after a failed health
	// check, a version mismatch, or an operator-requested rollback.
	StateRolledBack = "rolled_back"
	// StateFailed: the attempt ended without an installed new build and without
	// anything to restore (e.g. interrupted before the swap).
	StateFailed = "failed"
)

// JournalSchemaVersion is bumped only for an incompatible journal change. An
// unknown version is treated as unusable state and fails closed to a rollback.
const JournalSchemaVersion = 1

// journalName is the on-disk file name inside the update root.
const journalName = "update-journal.json"

// maxJournalBytes bounds what the recovery path is willing to parse.
const maxJournalBytes = 64 * 1024

// Journal is the durable record of one in-flight self-update attempt.
type Journal struct {
	SchemaVersion int    `json:"schema_version"`
	State         string `json:"state"`
	ReleaseID     string `json:"release_id"`
	CommandID     string `json:"command_id"`
	FromVersion   string `json:"from_version"`
	ToVersion     string `json:"to_version"`
	// Absolute paths captured at stage time. They are re-derived and compared at
	// recovery so a moved installation never restores a foreign binary.
	ExePath    string `json:"exe_path"`
	BackupPath string `json:"backup_path"`
	StagedPath string `json:"staged_path,omitempty"`
	// ArtifactSHA256 is the verified digest of the installed build; it is
	// re-checked before a restore so a tampered backup cannot be swapped in.
	ArtifactSHA256 string `json:"artifact_sha256"`
	BackupSHA256   string `json:"backup_sha256,omitempty"`
	StartedAt      string `json:"started_at"`
	// HealthDeadline is the absolute time by which the new build must have
	// reported healthy. A start after it rolls back rather than waiting.
	HealthDeadline string `json:"health_deadline"`
	// Attempts counts health-check resolutions. A repeatedly crashing new build
	// must not loop forever; the bound converts it into a terminal rollback.
	Attempts int    `json:"attempts"`
	Reason   string `json:"reason,omitempty"`
	// Reported records that the outcome was acknowledged by the server, so the
	// journal can be cleared without losing evidence.
	Reported bool `json:"reported"`
}

// JournalPath returns the journal location inside an update root.
func JournalPath(root string) string { return filepath.Join(root, journalName) }

// loadJournal returns (nil, nil) when no attempt is in flight.
func loadJournal(root string) (*Journal, error) {
	path := JournalPath(root)
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if info.Size() > maxJournalBytes {
		return nil, fmt.Errorf("update journal is implausibly large (%d bytes)", info.Size())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var journal Journal
	if err := json.Unmarshal(raw, &journal); err != nil {
		return nil, fmt.Errorf("parse update journal: %w", err)
	}
	if journal.SchemaVersion != JournalSchemaVersion {
		return nil, fmt.Errorf("unsupported update journal schema version %d", journal.SchemaVersion)
	}
	return &journal, nil
}

// saveJournal writes the journal atomically and fsyncs both the file and its
// directory, so a power loss leaves either the previous or the new state —
// never a truncated one.
func saveJournal(root string, journal *Journal) error {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	journal.SchemaVersion = JournalSchemaVersion
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return err
	}
	tmp := JournalPath(root) + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(encoded); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, JournalPath(root)); err != nil {
		os.Remove(tmp)
		return err
	}
	if dir, err := os.Open(root); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// clearJournal removes a resolved attempt record.
func clearJournal(root string) error {
	if err := os.Remove(JournalPath(root)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func parseJournalTime(raw string) (time.Time, bool) {
	value, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false
	}
	return value.UTC(), true
}
