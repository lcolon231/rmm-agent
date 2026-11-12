//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chattray

import (
	"context"
	_ "embed"
	"sync"
	"syscall"
	"unsafe"

	"github.com/lcolon231/rmm/agent/internal/chatpipe"
	"golang.org/x/sys/windows"
)

// The tray logo. Swapping this file needs no code change; a multi-resolution
// .ico is preferred so Windows can pick the right size for the notification area.
//
//go:embed nodelink.ico
var iconData []byte

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassEx        = user32.NewProc("RegisterClassExW")
	pCreateWindowEx         = user32.NewProc("CreateWindowExW")
	pDefWindowProc          = user32.NewProc("DefWindowProcW")
	pGetMessage             = user32.NewProc("GetMessageW")
	pTranslateMessage       = user32.NewProc("TranslateMessage")
	pDispatchMessage        = user32.NewProc("DispatchMessageW")
	pDestroyWindow          = user32.NewProc("DestroyWindow")
	pPostQuitMessage        = user32.NewProc("PostQuitMessage")
	pPostMessage            = user32.NewProc("PostMessageW")
	pRegisterWindowMessage  = user32.NewProc("RegisterWindowMessageW")
	pCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	pAppendMenu             = user32.NewProc("AppendMenuW")
	pTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	pDestroyMenu            = user32.NewProc("DestroyMenu")
	pGetCursorPos           = user32.NewProc("GetCursorPos")
	pSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	pGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	pCreateIconFromResource = user32.NewProc("CreateIconFromResourceEx")
	pShellNotifyIcon        = shell32.NewProc("Shell_NotifyIconW")
	pGetModuleHandle        = kernel32.NewProc("GetModuleHandleW")
	pCreateMutex            = kernel32.NewProc("CreateMutexW")
)

const (
	wmDestroy      = 0x0002
	wmApp          = 0x8000
	wmTrayCallback = wmApp + 1
	wmChatResult   = wmApp + 2

	nimAdd    = 0x0
	nimModify = 0x1
	nimDelete = 0x2

	nifMessage = 0x1
	nifIcon    = 0x2
	nifTip     = 0x4
	nifInfo    = 0x10

	niifWarning = 0x2

	tpmRightButton = 0x2
	tpmReturnCmd   = 0x100
	mfString       = 0x0

	smCxSmIcon = 49

	errAlreadyExists = 183
)

type notifyIconData struct {
	cbSize            uint32
	hWnd              windows.Handle
	uID               uint32
	uFlags            uint32
	uCallbackMessage  uint32
	hIcon             windows.Handle
	szTip             [128]uint16
	dwState           uint32
	dwStateMask       uint32
	szInfo            [256]uint16
	uVersionOrTimeout uint32
	szInfoTitle       [64]uint16
	dwInfoFlags       uint32
	guidItem          windows.GUID
	hBalloonIcon      windows.Handle
}

type point struct{ x, y int32 }

type msgStruct struct {
	hwnd     windows.Handle
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	pt       point
	lPrivate uint32
}

type wndClassEx struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     windows.Handle
	hIcon         windows.Handle
	hCursor       windows.Handle
	hbrBackground windows.Handle
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       windows.Handle
}

func loadIcon(data []byte) (windows.Handle, error) {
	want, _, _ := pGetSystemMetrics.Call(uintptr(smCxSmIcon))
	off, size, err := pickIcoEntry(data, int(want))
	if err != nil {
		return 0, err
	}
	h, _, _ := pCreateIconFromResource.Call(
		uintptr(unsafe.Pointer(&data[off])), uintptr(size), 1, 0x00030000,
		want, want, 0,
	)
	if h == 0 {
		return 0, ErrUnsupported
	}
	return windows.Handle(h), nil
}

func utf16(s string, out []uint16) {
	enc := windows.StringToUTF16(s)
	n := copy(out, enc)
	if n == len(out) {
		out[len(out)-1] = 0
	}
}

// trayAPI is the Win32 surface behind the tray's decisions. win32 binds it to
// user32/shell32; tests substitute fakes to drive wndProc without a desktop.
type trayAPI struct {
	notifyIcon    func(op uintptr, nid *notifyIconData)
	post          func(hwnd windows.Handle, msg uint32, wParam uintptr)
	defWindowProc func(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr
	postQuit      func()
	destroyWindow func(hwnd windows.Handle)
	popupMenu     func(hwnd windows.Handle) uintptr
	requestChat   func(context.Context) error
}

var win32 = trayAPI{
	notifyIcon: func(op uintptr, nid *notifyIconData) { pShellNotifyIcon.Call(op, uintptr(unsafe.Pointer(nid))) },
	post: func(hwnd windows.Handle, msg uint32, wParam uintptr) {
		pPostMessage.Call(uintptr(hwnd), uintptr(msg), wParam, 0)
	},
	defWindowProc: func(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
		r, _, _ := pDefWindowProc.Call(uintptr(hwnd), uintptr(msg), wParam, lParam)
		return r
	},
	postQuit:      func() { pPostQuitMessage.Call(0) },
	destroyWindow: func(hwnd windows.Handle) { pDestroyWindow.Call(uintptr(hwnd)) },
	popupMenu:     popupMenu,
	requestChat:   chatpipe.Request,
}

type tray struct {
	sys     trayAPI
	hwnd    windows.Handle
	hicon   windows.Handle
	taskbar uint32
	mu      sync.Mutex
	lastErr string
}

func (t *tray) baseIcon() notifyIconData {
	nid := notifyIconData{
		cbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:             t.hwnd,
		uID:              1,
		uFlags:           nifMessage | nifIcon | nifTip,
		uCallbackMessage: wmTrayCallback,
		hIcon:            t.hicon,
	}
	utf16("NodeLink Support", nid.szTip[:])
	return nid
}

func (t *tray) add() {
	nid := t.baseIcon()
	t.sys.notifyIcon(nimAdd, &nid)
}

func (t *tray) balloon(title, body string) {
	nid := t.baseIcon()
	nid.uFlags |= nifInfo
	nid.dwInfoFlags = niifWarning
	utf16(title, nid.szInfoTitle[:])
	utf16(body, nid.szInfo[:])
	t.sys.notifyIcon(nimModify, &nid)
}

func (t *tray) remove() {
	nid := notifyIconData{
		cbSize: uint32(unsafe.Sizeof(notifyIconData{})),
		hWnd:   t.hwnd,
		uID:    1,
	}
	t.sys.notifyIcon(nimDelete, &nid)
}

// openChat runs the same pipe request as `rmm-agent chat` off the UI thread and
// reports failure back to the message loop so a balloon is shown on that thread.
func (t *tray) openChat() {
	go func() {
		err := t.sys.requestChat(context.Background())
		ok := uintptr(1)
		if err != nil {
			t.mu.Lock()
			t.lastErr = err.Error()
			t.mu.Unlock()
			ok = 0
		}
		t.sys.post(t.hwnd, wmChatResult, ok)
	}()
}

// popupMenu shows the Open/Exit menu at the cursor and returns the chosen
// command, or 0 when dismissed.
func popupMenu(hwnd windows.Handle) uintptr {
	menu, _, _ := pCreatePopupMenu.Call()
	if menu == 0 {
		return 0
	}
	defer pDestroyMenu.Call(menu)
	open := windows.StringToUTF16Ptr("Open support chat")
	exit := windows.StringToUTF16Ptr("Exit")
	pAppendMenu.Call(menu, mfString, idOpen, uintptr(unsafe.Pointer(open)))
	pAppendMenu.Call(menu, mfString, idExit, uintptr(unsafe.Pointer(exit)))
	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	// A foreground window is required so the menu dismisses on outside clicks.
	pSetForegroundWindow.Call(uintptr(hwnd))
	cmd, _, _ := pTrackPopupMenu.Call(menu, tpmRightButton|tpmReturnCmd,
		uintptr(pt.x), uintptr(pt.y), 0, uintptr(hwnd), 0)
	return cmd
}

func (t *tray) showMenu() {
	switch actionForMenu(t.sys.popupMenu(t.hwnd)) {
	case actOpen:
		t.openChat()
	case actExit:
		t.sys.destroyWindow(t.hwnd)
	}
}

func (t *tray) wndProc(hwnd windows.Handle, msg uint32, wParam, lParam uintptr) uintptr {
	switch msg {
	case wmTrayCallback:
		switch actionForMessage(uint32(lParam) & 0xFFFF) {
		case actOpen:
			t.openChat()
		case actMenu:
			t.showMenu()
		}
		return 0
	case wmChatResult:
		if wParam == 0 {
			t.mu.Lock()
			body := t.lastErr
			t.mu.Unlock()
			t.balloon("NodeLink Support", failureBody(body))
		}
		return 0
	case wmDestroy:
		t.remove()
		t.sys.postQuit()
		return 0
	default:
		if t.taskbar != 0 && msg == t.taskbar {
			// Explorer restarted; re-add the icon.
			t.add()
			return 0
		}
	}
	return t.sys.defWindowProc(hwnd, msg, wParam, lParam)
}

func run() error {
	// One tray per interactive session. A second launch (e.g. a second Startup
	// trigger) exits quietly rather than stacking icons.
	name := windows.StringToUTF16Ptr(`Local\NodeLinkSupportTray`)
	if _, _, callErr := pCreateMutex.Call(0, 0, uintptr(unsafe.Pointer(name))); callErr == syscall.Errno(errAlreadyExists) {
		return nil
	}

	hicon, err := loadIcon(iconData)
	if err != nil {
		return err
	}
	t := &tray{sys: win32, hicon: hicon}

	hInst, _, _ := pGetModuleHandle.Call(0)
	className := windows.StringToUTF16Ptr("NodeLinkSupportTray")
	proc := windows.NewCallback(t.wndProc)
	wc := wndClassEx{
		cbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		lpfnWndProc:   proc,
		hInstance:     windows.Handle(hInst),
		lpszClassName: className,
	}
	if atom, _, _ := pRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); atom == 0 {
		return ErrUnsupported
	}

	hwnd, _, _ := pCreateWindowEx.Call(
		0, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(className)),
		0, 0, 0, 0, 0, 0, 0, hInst, 0,
	)
	if hwnd == 0 {
		return ErrUnsupported
	}
	t.hwnd = windows.Handle(hwnd)

	// Re-add the icon if Explorer restarts.
	tbc := windows.StringToUTF16Ptr("TaskbarCreated")
	tb, _, _ := pRegisterWindowMessage.Call(uintptr(unsafe.Pointer(tbc)))
	t.taskbar = uint32(tb)

	t.add()
	defer t.remove()

	var msg msgStruct
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		switch int32(r) {
		case 0, -1:
			return nil
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		pDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
}
