//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

var pGetConsoleWindow = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleWindow")

// hasConsole reports whether this process is attached to a console. The
// GUI-subsystem build (rmm-agent-tray.exe, -H=windowsgui) that the Start-menu
// and Startup shortcuts launch never gets one (issue #322), so its stdout and
// stderr go nowhere.
func hasConsole() bool {
	hwnd, _, _ := pGetConsoleWindow.Call()
	return hwnd != 0
}

// reportError shows err to the user: on stderr when a console is attached,
// otherwise in a dialog so a shortcut launch does not fail silently.
func reportError(err error) {
	if hasConsole() {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	text, _ := windows.UTF16PtrFromString(err.Error())
	caption, _ := windows.UTF16PtrFromString("NodeLink Support")
	_, _ = windows.MessageBox(0, text, caption, windows.MB_OK|windows.MB_ICONERROR)
}

// reportInfo prints a confirmation only when a console is attached; the GUI
// build stays silent on success because the browser opening is the feedback.
func reportInfo(msg string) {
	if hasConsole() {
		fmt.Println(msg)
	}
}
