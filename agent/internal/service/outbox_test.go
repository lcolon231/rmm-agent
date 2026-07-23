// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
)

func newOutbox(t *testing.T) *Outbox {
	t.Helper()
	o, err := LoadOutbox(filepath.Join(t.TempDir(), outboxFileName))
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestOutboxRoundTripAndRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, outboxFileName)
	o, err := LoadOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	o.Add("cmd-1", client.CommandResult{ExitCode: 0, Stdout: "hi"}, time.Now())
	if err := o.Save(); err != nil {
		t.Fatal(err)
	}

	// A fresh load (simulating an agent restart) sees the queued result.
	reloaded, err := LoadOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Has("cmd-1") || reloaded.Len() != 1 {
		t.Fatalf("reloaded outbox missing cmd-1: len=%d", reloaded.Len())
	}
	if got := reloaded.Pending()[0].Result.Stdout; got != "hi" {
		t.Fatalf("stdout = %q, want hi", got)
	}

	reloaded.Remove("cmd-1")
	if err := reloaded.Save(); err != nil {
		t.Fatal(err)
	}
	final, _ := LoadOutbox(path)
	if final.Len() != 0 {
		t.Fatalf("expected empty outbox after remove, len=%d", final.Len())
	}
}

func TestOutboxPendingIsDeterministicByQueuedAt(t *testing.T) {
	o := newOutbox(t)
	base := time.Unix(1000, 0)
	o.Add("b", client.CommandResult{}, base.Add(2*time.Second))
	o.Add("a", client.CommandResult{}, base.Add(1*time.Second))
	o.Add("c", client.CommandResult{}, base.Add(3*time.Second))
	got := []string{}
	for _, item := range o.Pending() {
		got = append(got, item.CommandID)
	}
	if want := []string{"a", "b", "c"}; !equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// resultServer is a fake result endpoint whose availability can be toggled to
// simulate a server outage, and which records every delivery it accepts.
type resultServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	delivered map[string]int // command id -> number of accepted deliveries
	fail      atomic.Bool
}

func newResultServer(t *testing.T) *resultServer {
	rs := &resultServer{delivered: map[string]int{}}
	rs.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rs.fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		parts := splitPath(r.URL.Path)
		id := ""
		if len(parts) >= 4 {
			id = parts[3] // /api/v1/commands/{id}/result
		}
		var res client.CommandResult
		_ = json.NewDecoder(r.Body).Decode(&res)
		rs.mu.Lock()
		rs.delivered[id]++
		rs.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(rs.srv.Close)
	return rs
}

func (rs *resultServer) count(id string) int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.delivered[id]
}

func splitPath(p string) []string {
	out := []string{}
	cur := ""
	for _, c := range p {
		if c == '/' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(c)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func agentWithOutbox(t *testing.T, srvURL, outboxPath string) (*Agent, *session) {
	t.Helper()
	o, err := LoadOutbox(outboxPath)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{log: log.New(&nopWriter{}, "", 0)}
	s := &session{api: client.New(srvURL, "tok"), agentID: "agent-1", outbox: o}
	return a, s
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// A completed result must survive a server outage: it is queued, delivery
// fails, and a later flush (once the server recovers) delivers it and clears
// the outbox.
func TestFlushRetriesQueuedResultAfterOutage(t *testing.T) {
	rs := newResultServer(t)
	path := filepath.Join(t.TempDir(), outboxFileName)
	a, s := agentWithOutbox(t, rs.srv.URL, path)

	s.outbox.Add("cmd-1", client.CommandResult{ExitCode: 0, Stdout: "done"}, time.Now())
	if err := s.outbox.Save(); err != nil {
		t.Fatal(err)
	}

	// Server is down: flush leaves the result queued.
	rs.fail.Store(true)
	a.flushOutbox(context.Background(), s)
	if s.outbox.Len() != 1 {
		t.Fatalf("result dropped during outage: len=%d", s.outbox.Len())
	}
	if rs.count("cmd-1") != 0 {
		t.Fatalf("delivery should not have succeeded during outage")
	}

	// Server recovers: flush delivers and clears the outbox, and the cleared
	// state is persisted.
	rs.fail.Store(false)
	a.flushOutbox(context.Background(), s)
	if s.outbox.Len() != 0 {
		t.Fatalf("result not cleared after successful delivery: len=%d", s.outbox.Len())
	}
	if rs.count("cmd-1") != 1 {
		t.Fatalf("expected exactly one delivery, got %d", rs.count("cmd-1"))
	}
	persisted, _ := LoadOutbox(path)
	if persisted.Len() != 0 {
		t.Fatalf("cleared outbox not persisted: len=%d", persisted.Len())
	}
}

// A result queued by a previous run (left on disk) is redelivered after an
// agent restart: a new outbox loaded from the same path flushes it.
func TestRestartRedeliversPendingResult(t *testing.T) {
	rs := newResultServer(t)
	path := filepath.Join(t.TempDir(), outboxFileName)

	// Previous run: execute, queue the result, but the process dies before the
	// server acknowledges (server was down).
	pre, err := LoadOutbox(path)
	if err != nil {
		t.Fatal(err)
	}
	pre.Add("cmd-42", client.CommandResult{ExitCode: 0, Stdout: "survived"}, time.Now())
	if err := pre.Save(); err != nil {
		t.Fatal(err)
	}

	// New run loads the outbox from disk and flushes it to a now-healthy server.
	a, s := agentWithOutbox(t, rs.srv.URL, path)
	if s.outbox.Len() != 1 {
		t.Fatalf("restart did not load pending result: len=%d", s.outbox.Len())
	}
	a.flushOutbox(context.Background(), s)
	if rs.count("cmd-42") != 1 || s.outbox.Len() != 0 {
		t.Fatalf("pending result not redelivered on restart: delivered=%d len=%d",
			rs.count("cmd-42"), s.outbox.Len())
	}
}

// A lost acknowledgement (agent delivered but never saw the 204) is safe:
// the result stays queued and is re-sent. The server is idempotent, so the
// operator record is unaffected; here we assert the agent re-sends until it
// records success.
func TestLostAckLeavesResultQueuedForRetry(t *testing.T) {
	rs := newResultServer(t)
	path := filepath.Join(t.TempDir(), outboxFileName)
	a, s := agentWithOutbox(t, rs.srv.URL, path)
	s.outbox.Add("cmd-9", client.CommandResult{ExitCode: 1, Stderr: "boom"}, time.Now())

	// First attempt fails (treated as a lost ack from the agent's view).
	rs.fail.Store(true)
	a.flushOutbox(context.Background(), s)
	if s.outbox.Len() != 1 {
		t.Fatal("result should remain queued after a failed delivery")
	}
	// Retry succeeds.
	rs.fail.Store(false)
	a.flushOutbox(context.Background(), s)
	if s.outbox.Len() != 0 {
		t.Fatal("result should clear after a successful retry")
	}
}
