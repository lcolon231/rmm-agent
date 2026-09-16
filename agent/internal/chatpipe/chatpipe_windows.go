//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatpipe

import (
	"context"
	"golang.org/x/sys/windows"
	"time"
	"unsafe"
)

// Grant a client exactly what CreateFile needs to open and exchange one message:
// FILE_READ_DATA(0x1) | FILE_WRITE_DATA(0x2) | FILE_READ_ATTRIBUTES(0x80) |
// FILE_WRITE_ATTRIBUTES(0x100) | SYNCHRONIZE(0x100000). CreateFile always
// implicitly requests FILE_READ_ATTRIBUTES, so omitting 0x80 denies every open.
// Deliberately excludes FILE_APPEND_DATA(0x4), which on a pipe is
// FILE_CREATE_PIPE_INSTANCE -- never grant GENERIC_WRITE/FRFW, which include it.
// SYSTEM owns the server. Only INTERACTIVE may connect as a client.
const pipeACL = "D:P(A;;GA;;;SY)(A;;0x00100183;;;IU)"
const pipeMode = windows.PIPE_TYPE_MESSAGE | windows.PIPE_READMODE_MESSAGE | windows.PIPE_NOWAIT | windows.PIPE_REJECT_REMOTE_CLIENTS

var clientSession = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetNamedPipeClientSessionId")

func newPipe(name string) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeACL)
	if err != nil {
		return 0, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	path, _ := windows.UTF16PtrFromString(name)
	return windows.CreateNamedPipe(path, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, pipeMode, 1, 1, 256, 0, &sa)
}

func Serve(ctx context.Context, handle Handler) error { return serve(ctx, Name, handle) }
func serve(ctx context.Context, name string, handle Handler) error {
	pipe, err := newPipe(name)
	if err != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(pipe)
	limiter := SessionLimiter{}
	for ctx.Err() == nil {
		err := windows.ConnectNamedPipe(pipe, nil)
		if err == windows.ERROR_PIPE_LISTENING {
			if !pause(ctx) {
				break
			}
			continue
		}
		if err == windows.ERROR_NO_DATA {
			windows.DisconnectNamedPipe(pipe)
			continue
		}
		if err != nil && err != windows.ERROR_PIPE_CONNECTED {
			return ErrUnavailable
		}
		serveClient(ctx, pipe, limiter, handle)
		windows.DisconnectNamedPipe(pipe)
	}
	return nil
}

func serveClient(ctx context.Context, pipe windows.Handle, limiter SessionLimiter, handle Handler) {
	requestCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	deadline := time.Now().Add(2 * time.Second)
	var buf [1]byte
	var n uint32
	for time.Now().Before(deadline) {
		err := windows.ReadFile(pipe, buf[:], &n, nil)
		// A one-byte opcode is the complete request. Extra bytes are discarded when
		// the connection closes and can never become a URL, identity or session.
		if (err == nil || err == windows.ERROR_MORE_DATA) && n == 1 {
			break
		}
		if err != windows.ERROR_NO_DATA || !pause(requestCtx) {
			return
		}
	}
	if n != 1 || buf[0] != openRequest {
		return
	}
	var session uint32
	ok, _, _ := clientSession.Call(uintptr(pipe), uintptr(unsafe.Pointer(&session)))
	status := byte(0)
	if ok != 0 && limiter.Allow(session, time.Now()) && handle(requestCtx, session) == nil {
		status = 1
	}
	windows.WriteFile(pipe, []byte{status}, &n, nil)
	// Never FlushFileBuffers: a malicious client could block service shutdown.
	// Wait at most 1s for the client to consume the one-byte, non-secret status.
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		err := windows.ReadFile(pipe, buf[:], &n, nil)
		if err == windows.ERROR_BROKEN_PIPE || (err == nil && n == 1) || !pause(requestCtx) {
			return
		}
	}
}

func Request(ctx context.Context) error { return request(ctx, Name) }
func request(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	path, _ := windows.UTF16PtrFromString(name)
	pipe, err := windows.CreateFile(path, windows.FILE_READ_DATA|windows.FILE_WRITE_DATA|windows.FILE_WRITE_ATTRIBUTES, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer windows.CloseHandle(pipe)
	mode := uint32(windows.PIPE_READMODE_MESSAGE | windows.PIPE_NOWAIT)
	if windows.SetNamedPipeHandleState(pipe, &mode, nil, nil) != nil {
		return ErrUnavailable
	}
	var n uint32
	if windows.WriteFile(pipe, []byte{openRequest}, &n, nil) != nil {
		return ErrUnavailable
	}
	var reply [1]byte
	for ctx.Err() == nil {
		err = windows.ReadFile(pipe, reply[:], &n, nil)
		if err == nil && n == 1 {
			windows.WriteFile(pipe, []byte{0}, &n, nil)
			if reply[0] == 1 {
				return nil
			}
			return ErrRefused
		}
		if err != windows.ERROR_NO_DATA || !pause(ctx) {
			break
		}
	}
	return ErrRefused
}
