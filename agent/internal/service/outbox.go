// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
)

// Outbox is a durable store of completed command results awaiting delivery
// (issue #113). A result is written here the instant a command finishes, before
// any upload is attempted, so a completed command's result survives a server
// outage or an agent restart and is retried until the server acknowledges it.
//
// Execution stays exactly-once: the replay reservation (SeenStore) is persisted
// before the process starts, so a command already executed is never re-run after
// a restart. Delivery is at-least-once: the same result may be uploaded more
// than once (the server treats duplicate deliveries idempotently).
//
// Like SeenStore, it is used from the single check-in goroutine and does no
// locking of its own; it persists to one atomically written file beside
// identity.json.
type Outbox struct {
	path    string
	entries map[string]outboxEntry
}

// outboxEntry is one completed result keyed by command ID. QueuedAt gives a
// stable delivery order and lets an operator reason about delivery lag.
type outboxEntry struct {
	Result   client.CommandResult `json:"result"`
	QueuedAt time.Time            `json:"queued_at"`
}

const outboxFileName = "result_outbox.json"

// OutboxPath returns the store path beside the config/identity files.
func OutboxPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), outboxFileName)
}

// LoadOutbox reads the persisted outbox from path, returning an empty outbox if
// the file does not exist yet. A corrupt/unreadable file (other than not-exist)
// is reported so the caller can decide how to proceed.
func LoadOutbox(path string) (*Outbox, error) {
	o := &Outbox{path: path, entries: make(map[string]outboxEntry)}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return o, nil
		}
		return nil, fmt.Errorf("read result outbox %s: %w", path, err)
	}
	if len(data) == 0 {
		return o, nil
	}
	if err := json.Unmarshal(data, &o.entries); err != nil {
		return nil, fmt.Errorf("parse result outbox: %w", err)
	}
	if o.entries == nil {
		o.entries = make(map[string]outboxEntry)
	}
	return o, nil
}

// Add records a completed result for commandID. If one is already queued for
// that ID (a re-execution can never happen, but a repeated enqueue is harmless)
// the original QueuedAt is preserved so delivery order is stable.
func (o *Outbox) Add(commandID string, result client.CommandResult, now time.Time) {
	if existing, ok := o.entries[commandID]; ok {
		existing.Result = result
		o.entries[commandID] = existing
		return
	}
	o.entries[commandID] = outboxEntry{Result: result, QueuedAt: now}
}

// Remove drops the queued result for commandID once the server has acknowledged
// delivery.
func (o *Outbox) Remove(commandID string) {
	delete(o.entries, commandID)
}

// Has reports whether a result is queued for commandID.
func (o *Outbox) Has(commandID string) bool {
	_, ok := o.entries[commandID]
	return ok
}

// Len is the number of results awaiting delivery.
func (o *Outbox) Len() int { return len(o.entries) }

// pendingItem pairs a command ID with its queued result for delivery.
type pendingItem struct {
	CommandID string
	Result    client.CommandResult
}

// Pending returns the queued results in stable QueuedAt order (ties broken by
// command ID) so delivery is deterministic.
func (o *Outbox) Pending() []pendingItem {
	items := make([]pendingItem, 0, len(o.entries))
	ids := make([]string, 0, len(o.entries))
	for id := range o.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		a, b := o.entries[ids[i]], o.entries[ids[j]]
		if a.QueuedAt.Equal(b.QueuedAt) {
			return ids[i] < ids[j]
		}
		return a.QueuedAt.Before(b.QueuedAt)
	})
	for _, id := range ids {
		items = append(items, pendingItem{CommandID: id, Result: o.entries[id].Result})
	}
	return items
}

// Save writes the outbox atomically (temp file + rename, 0600) so a crash mid-
// write cannot leave a truncated file.
func (o *Outbox) Save() error {
	data, err := json.Marshal(o.entries)
	if err != nil {
		return err
	}
	dir := filepath.Dir(o.path)
	tmp, err := os.CreateTemp(dir, outboxFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp result outbox: %w", err)
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
	if err := os.Rename(tmpName, o.path); err != nil {
		return fmt.Errorf("rename result outbox into place: %w", err)
	}
	return nil
}
