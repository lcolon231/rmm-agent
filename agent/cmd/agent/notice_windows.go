//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"golang.org/x/sys/windows"
)

var pGetConsoleWindow = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")

// hasConsole reports whether this process is attached to a console window.
// The GUI-subsystem build (rmm-agent-tray.exe, -H=windowsgui) launched from a
// shortcut has none, so its stdout/stderr go nowhere (issue #322).
func hasConsole() bool {
	if err := pGetConsoleWindow.Find(); err != nil {
		return true // cannot tell; keep the console behaviour
	}
	h, _, _ := pGetConsoleWindow.Call()
	return h != 0
}

// showUserError shows msg in a modal error dialog titled "NodeLink Support".
func showUserError(msg string) {
	title, _ := windows.UTF16PtrFromString("NodeLink Support")
	text, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return
	}
	windows.MessageBox(0, text, title, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
}
