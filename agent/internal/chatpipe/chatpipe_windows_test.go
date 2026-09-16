//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatpipe

import (
	"context"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func TestRemotePipeClientsRejected(t *testing.T) {
	// CreateNamedPipe's PIPE_REJECT_REMOTE_CLIENTS maps to the native
	// FILE_PIPE_REJECT_REMOTE_CLIENTS option. These are different numeric flags.
	if pipeMode&windows.PIPE_REJECT_REMOTE_CLIENTS == 0 {
		t.Fatal("remote clients enabled")
	}
	name := fmt.Sprintf(`\\.\pipe\nodelink-chat-test-%d-remote`, os.Getpid())
	pipe, err := newPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	remote := strings.Replace(name, `\\.\`, `\\127.0.0.1\`, 1)
	p, _ := windows.UTF16PtrFromString(remote)
	h, err := windows.CreateFile(p, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		windows.CloseHandle(h)
		t.Fatal("remote client connected")
	}
	if err != windows.ERROR_ACCESS_DENIED {
		t.Skipf("SMB loopback unavailable; remote-rejection flag asserted, native denial requires SMB: %v", err)
	}
}

func TestNonInteractiveCallerDenied(t *testing.T) {
	// Prove a caller whose token is not a member of INTERACTIVE is refused at
	// connect time against the real pipe. This exercises newPipe's actual DACL
	// (including the FILE_READ_ATTRIBUTES the client needs) rather than an
	// AccessCheck against a re-parsed SDDL string, which was fragile and does not
	// prove a real open would fail.
	name := fmt.Sprintf(`\\.\pipe\nodelink-chat-test-%d-noninteractive`, os.Getpid())
	pipe, err := newPipe(name)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)

	var process windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &process); err != nil {
		t.Fatal(err)
	}
	defer process.Close()

	// Turn INTERACTIVE into a deny-only SID so the (A;;...;;;IU) ACE cannot grant
	// access. CreateRestrictedToken needs only TOKEN_DUPLICATE, no privilege.
	interactive, _ := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	disable := []windows.SIDAndAttributes{{Sid: interactive}}
	var restricted windows.Token
	create := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	ok, _, e := create.Call(uintptr(process), 0, uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])), 0, 0, 0, 0, uintptr(unsafe.Pointer(&restricted)))
	if ok == 0 {
		t.Fatal(e)
	}
	defer restricted.Close()

	var impersonation windows.Token
	if err = windows.DuplicateTokenEx(restricted, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE, nil, windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		t.Fatal(err)
	}
	defer impersonation.Close()

	// SetThreadToken affects one OS thread; pin CreateFile to it, then revert.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err = windows.SetThreadToken(nil, impersonation); err != nil {
		t.Fatal(err)
	}
	defer windows.RevertToSelf()

	p, _ := windows.UTF16PtrFromString(name)
	h, err := windows.CreateFile(p, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err == nil {
		windows.CloseHandle(h)
		t.Fatal("non-interactive caller connected")
	}
	if err != windows.ERROR_ACCESS_DENIED {
		t.Fatalf("expected access denied, got %v", err)
	}
}

func TestExtraBytesDoNotSupplyParametersAndShutdownIsBounded(t *testing.T) {
	interactive, _ := windows.CreateWellKnownSid(windows.WinInteractiveSid)
	member, err := windows.Token(0).IsMember(interactive)
	if err != nil || !member {
		t.Skip("positive pipe test needs an interactive user token")
	}
	name := fmt.Sprintf(`\\.\pipe\nodelink-chat-test-%d-extra`, os.Getpid())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := make(chan uint32, 1)
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, name, func(_ context.Context, id uint32) error { called <- id; return nil })
	}()
	p, _ := windows.UTF16PtrFromString(name)
	var pipe windows.Handle
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		pipe, err = windows.CreateFile(p, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA, 0, nil, windows.OPEN_EXISTING, 0, 0)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(pipe)
	data := append([]byte{openRequest}, []byte("https://attacker.test/?agent_id=wrong")...)
	var n uint32
	if err = windows.WriteFile(pipe, data, &n, nil); err != nil {
		t.Fatal(err)
	}
	var expected uint32
	if err = windows.ProcessIdToSessionId(uint32(os.Getpid()), &expected); err != nil {
		t.Fatal(err)
	}
	select {
	case actual := <-called:
		if actual != expected {
			t.Fatal("session came from payload")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("handler not called")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown blocked on pipe client")
	}
	select {
	case <-called:
		t.Fatal("extra bytes became another request")
	default:
	}
}

func TestChatReportsMissingServiceWithoutWaiting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if request(ctx, `\\.\pipe\nodelink-chat-absent-test`) != ErrUnavailable {
		t.Fatal("missing service not reported")
	}
}
