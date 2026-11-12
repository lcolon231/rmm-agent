//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatpipe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// userACL grants the test's own token the production client mask. CI runners
// log on as a service, not INTERACTIVE, so pipeACL itself would deny them; the
// mask is unchanged, so these tests still prove it suffices for a real open.
func userACL(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	acl := strings.Replace(pipeACL, ";;;IU)", ";;;"+user.User.Sid.String()+")", 1)
	if acl == pipeACL {
		t.Fatal("pipeACL no longer has an INTERACTIVE client ACE to substitute")
	}
	return acl
}

func pipeName(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\nodelink-chat-test-%d-%s`, os.Getpid(), strings.ReplaceAll(t.Name(), "/", "-"))
}

func processSession(t *testing.T) uint32 {
	t.Helper()
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		t.Fatal(err)
	}
	return session
}

// startServer runs serve until the test ends and fails the test if shutdown
// does not return promptly.
func startServer(t *testing.T, name string, handle Handler) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, name, userACL(t), handle) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve returned %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("serve did not stop after cancel")
		}
	})
}

// dial waits for the single pipe instance to be free and connects a raw client.
func dial(t *testing.T, name string) windows.Handle {
	t.Helper()
	path, _ := windows.UTF16PtrFromString(name)
	var err error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var pipe windows.Handle
		pipe, err = windows.CreateFile(path, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA|windows.FILE_WRITE_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			mode := uint32(windows.PIPE_READMODE_MESSAGE | windows.PIPE_NOWAIT)
			if err = windows.SetNamedPipeHandleState(pipe, &mode, nil, nil); err != nil {
				t.Fatal(err)
			}
			return pipe
		}
	}
	t.Fatalf("connect %s: %v", name, err)
	return 0
}

// awaitReply polls for the server's one-byte status. got is false when the
// server hung up without answering.
func awaitReply(t *testing.T, pipe windows.Handle) (status byte, got bool) {
	t.Helper()
	var buf [1]byte
	var n uint32
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		err := windows.ReadFile(pipe, buf[:], &n, nil)
		if err == nil && n == 1 {
			return buf[0], true
		}
		if err != windows.ERROR_NO_DATA {
			return 0, false
		}
	}
	t.Fatal("server neither replied nor disconnected")
	return 0, false
}

// requestWithin retries ErrUnavailable while the server goroutine creates the
// pipe or a previous client still holds the single instance. ErrUnavailable is
// only returned before the opcode is sent, so a retry can never double-open.
func requestWithin(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		err := request(ctx, name)
		if err != ErrUnavailable || !pause(ctx) {
			return err
		}
	}
}

func TestRequestRoundTripReportsHandlerOutcome(t *testing.T) {
	tests := []struct {
		name    string
		handler error
		want    error
	}{
		{"opened", nil, nil},
		{"handler refused", errors.New("no browser"), ErrRefused},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name := pipeName(t)
			sessions := make(chan uint32, 1)
			startServer(t, name, func(_ context.Context, session uint32) error {
				sessions <- session
				return tt.handler
			})
			if err := requestWithin(name); err != tt.want {
				t.Fatalf("request = %v, want %v", err, tt.want)
			}
			// The session comes from the kernel, never the client's bytes.
			if got := <-sessions; got != processSession(t) {
				t.Fatalf("handler got session %d, want %d", got, processSession(t))
			}
		})
	}
}

func TestRepeatRequestFromSameSessionIsRateLimited(t *testing.T) {
	name := pipeName(t)
	var calls atomic.Int32
	startServer(t, name, func(context.Context, uint32) error { calls.Add(1); return nil })
	if err := requestWithin(name); err != nil {
		t.Fatalf("first request = %v", err)
	}
	if err := requestWithin(name); err != ErrRefused {
		t.Fatalf("second request = %v, want ErrRefused", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times, want 1", calls.Load())
	}
}

func TestMalformedRequestsNeverReachHandler(t *testing.T) {
	name := pipeName(t)
	var calls atomic.Int32
	startServer(t, name, func(context.Context, uint32) error { calls.Add(1); return nil })
	tests := []struct {
		name    string
		message []byte // nil: connect and send nothing until the read deadline
		hangUp  bool   // close before sending anything
	}{
		{"unknown opcode", []byte{2}, false},
		{"unknown opcode with payload", append([]byte{0}, strings.Repeat("A", 255)...), false},
		{"empty message", []byte{}, false},
		{"silent client", nil, false},
		{"immediate hang-up", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pipe := dial(t, name)
			if tt.hangUp {
				windows.CloseHandle(pipe)
				return
			}
			defer windows.CloseHandle(pipe)
			if tt.message != nil {
				var n uint32
				if err := windows.WriteFile(pipe, tt.message, &n, nil); err != nil {
					t.Fatal(err)
				}
			}
			if status, got := awaitReply(t, pipe); got {
				t.Fatalf("server answered malformed request with %d", status)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("handler ran %d times for malformed requests", calls.Load())
	}
	// The loop survives every malformed client and still serves a real one.
	if err := requestWithin(name); err != nil {
		t.Fatalf("valid request after malformed ones = %v", err)
	}
}

func TestOversizedMessageIsRefusedByThePipe(t *testing.T) {
	name := pipeName(t)
	startServer(t, name, func(context.Context, uint32) error { return nil })
	pipe := dial(t, name)
	defer windows.CloseHandle(pipe)
	// A nonblocking message write larger than the 256-byte inbound buffer
	// cannot be queued whole, so it never reaches serveClient as a request.
	var n uint32
	err := windows.WriteFile(pipe, append([]byte{openRequest}, make([]byte, 4096)...), &n, nil)
	if err == nil && n != 0 {
		t.Fatalf("oversized message accepted: %d bytes written", n)
	}
}

func TestRequestRefusedWhenServerNeverReplies(t *testing.T) {
	name := pipeName(t)
	pipe, err := newPipe(name, userACL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := request(ctx, name); err != ErrRefused {
		t.Fatalf("request = %v, want ErrRefused", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("request ignored its context deadline")
	}
}

func TestServeRefusesNameAlreadyOwned(t *testing.T) {
	name := pipeName(t)
	squatter, err := newPipe(name, userACL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(squatter)
	// FILE_FLAG_FIRST_PIPE_INSTANCE: never share a name another process created.
	if err := serve(context.Background(), name, userACL(t), nil); err != ErrUnavailable {
		t.Fatalf("serve = %v, want ErrUnavailable", err)
	}
}

func TestNewPipeRejectsInvalidACL(t *testing.T) {
	if _, err := newPipe(pipeName(t), "not an SDDL string"); err == nil {
		t.Fatal("invalid DACL accepted")
	}
}

func TestPublicServeAndRequestUseServiceName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A cancelled Serve returns at once: nil, or ErrUnavailable when an installed
	// NodeLinkAgent already owns the name. It never reaches a client.
	if err := Serve(ctx, nil); err != nil && err != ErrUnavailable {
		t.Fatalf("Serve = %v", err)
	}

	probe, err := newPipe(Name, userACL(t))
	if err != nil {
		t.Skipf("%s is owned by an installed agent; not exercising Request against it", Name)
	}
	windows.CloseHandle(probe)
	opened := make(chan struct{}, 1)
	startServer(t, Name, func(context.Context, uint32) error { opened <- struct{}{}; return nil })
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := Request(ctx); err != nil {
		t.Fatalf("Request = %v", err)
	}
	<-opened
}
