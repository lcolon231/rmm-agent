//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chattray

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const testHwnd windows.Handle = 0x1234

type notifyCall struct {
	op  uintptr
	nid notifyIconData
}

type postCall struct {
	msg    uint32
	wParam uintptr
}

// fakeShell records the tray's Win32 calls. requestChat runs on openChat's
// goroutine, so everything it touches is guarded or delivered by channel.
type fakeShell struct {
	mu        sync.Mutex
	notifies  []notifyCall
	quits     int
	destroyed []windows.Handle
	defCalls  []uint32
	menuCmd   uintptr
	menus     int
	chatErr   error
	requests  chan struct{}
	posts     chan postCall
}

func newFakeShell() *fakeShell {
	return &fakeShell{requests: make(chan struct{}, 4), posts: make(chan postCall, 4)}
}

func (f *fakeShell) api() trayAPI {
	return trayAPI{
		notifyIcon: func(op uintptr, nid *notifyIconData) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.notifies = append(f.notifies, notifyCall{op, *nid})
		},
		post: func(hwnd windows.Handle, msg uint32, wParam uintptr) {
			if hwnd == testHwnd {
				f.posts <- postCall{msg, wParam}
			}
		},
		defWindowProc: func(_ windows.Handle, msg uint32, _, _ uintptr) uintptr {
			f.defCalls = append(f.defCalls, msg)
			return 0xBEEF
		},
		postQuit:      func() { f.quits++ },
		destroyWindow: func(hwnd windows.Handle) { f.destroyed = append(f.destroyed, hwnd) },
		popupMenu:     func(windows.Handle) uintptr { f.menus++; return f.menuCmd },
		requestChat: func(context.Context) error {
			f.requests <- struct{}{}
			return f.chatErr
		},
	}
}

func (f *fakeShell) notified() []notifyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]notifyCall(nil), f.notifies...)
}

func newTestTray(f *fakeShell) *tray {
	return &tray{sys: f.api(), hwnd: testHwnd, hicon: 0x99, taskbar: 0xC123}
}

func expectRequest(t *testing.T, f *fakeShell, want bool) {
	t.Helper()
	select {
	case <-f.requests:
		if !want {
			t.Fatal("chat was requested")
		}
	case <-time.After(func() time.Duration {
		if want {
			return 3 * time.Second
		}
		return 100 * time.Millisecond
	}()):
		if want {
			t.Fatal("chat was not requested")
		}
	}
}

func TestTrayClicksDispatchToChatOrMenu(t *testing.T) {
	tests := []struct {
		name     string
		event    uintptr
		menuCmd  uintptr
		request  bool
		menu     bool
		destroys bool
	}{
		{"left click opens chat", wmLButtonUp, 0, true, false, false},
		// Shell_NotifyIcon v4 packs the icon id in the high word of lParam.
		{"high word ignored", 0x0001_0000 | wmLButtonDbl, 0, true, false, false},
		{"menu open", wmRButtonUp, idOpen, true, true, false},
		{"menu exit", wmContextMenu, idExit, false, true, true},
		{"menu dismissed", wmRButtonUp, 0, false, true, false},
		{"hover ignored", 0x0200, 0, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeShell()
			f.menuCmd = tt.menuCmd
			tr := newTestTray(f)
			if r := tr.wndProc(testHwnd, wmTrayCallback, 0, tt.event); r != 0 {
				t.Fatalf("wndProc returned %d", r)
			}
			expectRequest(t, f, tt.request)
			if (f.menus == 1) != tt.menu {
				t.Fatalf("menus shown = %d, want menu=%v", f.menus, tt.menu)
			}
			if (len(f.destroyed) == 1 && f.destroyed[0] == testHwnd) != tt.destroys {
				t.Fatalf("destroyed %v, want destroy=%v", f.destroyed, tt.destroys)
			}
			if len(f.defCalls) != 0 {
				t.Fatal("tray callback fell through to DefWindowProc")
			}
		})
	}
}

func TestOpenChatPostsResultToUIThread(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wParam  uintptr
		lastErr string
	}{
		{"opened", nil, 1, ""},
		{"failed", errors.New("NodeLink Support is unavailable"), 0, "NodeLink Support is unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeShell()
			f.chatErr = tt.err
			tr := newTestTray(f)
			tr.openChat()
			select {
			case p := <-f.posts:
				if p.msg != wmChatResult || p.wParam != tt.wParam {
					t.Fatalf("posted msg 0x%x wParam %d, want 0x%x %d", p.msg, p.wParam, wmChatResult, tt.wParam)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("result never posted")
			}
			tr.mu.Lock()
			defer tr.mu.Unlock()
			if tr.lastErr != tt.lastErr {
				t.Fatalf("lastErr = %q, want %q", tr.lastErr, tt.lastErr)
			}
			if len(f.notified()) != 0 {
				t.Fatal("balloon shown off the UI thread")
			}
		})
	}
}

func TestChatResultShowsBalloonOnlyOnFailure(t *testing.T) {
	tests := []struct {
		name    string
		wParam  uintptr
		lastErr string
		balloon string // "" means no balloon
	}{
		{"success is silent", 1, "stale error", ""},
		{"failure shows error", 0, "service stopped", "service stopped"},
		{"failure without text", 0, "", "NodeLink Support could not open."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeShell()
			tr := newTestTray(f)
			tr.lastErr = tt.lastErr
			tr.wndProc(testHwnd, wmChatResult, tt.wParam, 0)
			calls := f.notified()
			if tt.balloon == "" {
				if len(calls) != 0 {
					t.Fatalf("unexpected balloon %v", calls)
				}
				return
			}
			if len(calls) != 1 || calls[0].op != nimModify {
				t.Fatalf("calls %v, want one NIM_MODIFY", calls)
			}
			nid := calls[0].nid
			if nid.uFlags&nifInfo == 0 || nid.dwInfoFlags != niifWarning || nid.hIcon != 0x99 || nid.hWnd != testHwnd {
				t.Fatalf("balloon flags 0x%x info 0x%x icon %v hwnd %v", nid.uFlags, nid.dwInfoFlags, nid.hIcon, nid.hWnd)
			}
			if got := windows.UTF16ToString(nid.szInfo[:]); got != tt.balloon {
				t.Fatalf("balloon body %q, want %q", got, tt.balloon)
			}
			if got := windows.UTF16ToString(nid.szInfoTitle[:]); got != "NodeLink Support" {
				t.Fatalf("balloon title %q", got)
			}
		})
	}
}

func TestDestroyRemovesIconAndQuits(t *testing.T) {
	f := newFakeShell()
	tr := newTestTray(f)
	tr.wndProc(testHwnd, wmDestroy, 0, 0)
	calls := f.notified()
	if len(calls) != 1 || calls[0].op != nimDelete || calls[0].nid.uID != 1 || calls[0].nid.hWnd != testHwnd {
		t.Fatalf("calls %v, want one NIM_DELETE of icon 1", calls)
	}
	if f.quits != 1 {
		t.Fatalf("PostQuitMessage called %d times", f.quits)
	}
}

func TestExplorerRestartReAddsIcon(t *testing.T) {
	f := newFakeShell()
	tr := newTestTray(f)
	if r := tr.wndProc(testHwnd, tr.taskbar, 0, 0); r != 0 {
		t.Fatalf("wndProc returned %d", r)
	}
	calls := f.notified()
	if len(calls) != 1 || calls[0].op != nimAdd {
		t.Fatalf("calls %v, want one NIM_ADD", calls)
	}
	nid := calls[0].nid
	if nid.uCallbackMessage != wmTrayCallback || nid.uFlags != nifMessage|nifIcon|nifTip {
		t.Fatalf("callback 0x%x flags 0x%x", nid.uCallbackMessage, nid.uFlags)
	}
	if got := windows.UTF16ToString(nid.szTip[:]); got != "NodeLink Support" {
		t.Fatalf("tooltip %q", got)
	}
}

func TestOtherMessagesGoToDefWindowProc(t *testing.T) {
	f := newFakeShell()
	tr := newTestTray(f)
	tr.taskbar = 0 // RegisterWindowMessage failed: never match message 0
	for _, msg := range []uint32{0, 0x000F} {
		if r := tr.wndProc(testHwnd, msg, 0, 0); r != 0xBEEF {
			t.Fatalf("wndProc(0x%x) returned 0x%x, want DefWindowProc's result", msg, r)
		}
	}
	if len(f.defCalls) != 2 || len(f.notified()) != 0 {
		t.Fatalf("def calls %v, notifies %v", f.defCalls, f.notified())
	}
}

func TestUTF16TruncatesWithTerminator(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"short", "short"},
		{strings.Repeat("x", 7), strings.Repeat("x", 7)},
		{strings.Repeat("x", 8), strings.Repeat("x", 7)},
		{strings.Repeat("x", 300), strings.Repeat("x", 7)},
	}
	for _, tt := range tests {
		var out [8]uint16
		utf16(tt.in, out[:])
		if out[len(out)-1] != 0 && len(tt.in) >= len(out) {
			t.Fatalf("%d chars: missing terminator", len(tt.in))
		}
		if got := windows.UTF16ToString(out[:]); got != tt.want {
			t.Fatalf("utf16(%d chars) = %q, want %q", len(tt.in), got, tt.want)
		}
	}
}

func TestLoadIconCreatesHandleFromEmbeddedAsset(t *testing.T) {
	h, err := loadIcon(iconData)
	if err != nil || h == 0 {
		t.Fatalf("loadIcon = %v, %v", h, err)
	}
	if _, err := loadIcon([]byte{0, 0, 1, 0, 0, 0}); err == nil {
		t.Fatal("loadIcon accepted an empty container")
	}
}
