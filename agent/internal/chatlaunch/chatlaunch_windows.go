//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatlaunch

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

// api is the Win32 surface ForSession needs. Production binds it straight to
// x/sys/windows; tests substitute fakes so the session, token and process
// decisions run without a second logged-on user or a real browser launch.
type api struct {
	activeConsole       func() uint32
	queryUserToken      func(uint32, *windows.Token) error
	duplicateTokenEx    func(windows.Token, uint32, *windows.SecurityAttributes, uint32, uint32, *windows.Token) error
	closeHandle         func(windows.Handle) error
	systemDirectory     func() (string, error)
	createEnvironment   func(**uint16, windows.Token, bool) error
	destroyEnvironment  func(*uint16) error
	createProcessAsUser func(windows.Token, *uint16, *uint16, *windows.SecurityAttributes, *windows.SecurityAttributes, bool, uint32, *uint16, *uint16, *windows.StartupInfo, *windows.ProcessInformation) error
}

var system = api{
	activeConsole:       windows.WTSGetActiveConsoleSessionId,
	queryUserToken:      windows.WTSQueryUserToken,
	duplicateTokenEx:    windows.DuplicateTokenEx,
	closeHandle:         windows.CloseHandle,
	systemDirectory:     windows.GetSystemDirectory,
	createEnvironment:   windows.CreateEnvironmentBlock,
	destroyEnvironment:  windows.DestroyEnvironmentBlock,
	createProcessAsUser: windows.CreateProcessAsUser,
}

func ForSession(session uint32) (*Target, error) { return forSession(system, session) }

func forSession(sys api, session uint32) (*Target, error) {
	if session == 0 || session == 0xffffffff {
		return nil, ErrNoSession
	}
	var user windows.Token
	if err := sys.queryUserToken(session, &user); err != nil {
		return nil, ErrNoSession
	}
	defer sys.closeHandle(windows.Handle(user))
	var primary windows.Token
	if err := sys.duplicateTokenEx(user, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return nil, ErrLaunch
	}
	return &Target{release: func() { sys.closeHandle(windows.Handle(primary)) }, launch: func(raw string) error {
		directory, err := sys.systemDirectory()
		if err != nil {
			return ErrLaunch
		}
		executable := filepath.Join(directory, "rundll32.exe")
		app, _ := windows.UTF16PtrFromString(executable)
		// Both arguments are fixed or a validated HTTPS URL; no command shell runs.
		command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{executable, "url.dll,FileProtocolHandler", raw}))
		if err != nil {
			return ErrLaunch
		}
		desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
		var env *uint16
		if err := sys.createEnvironment(&env, primary, false); err != nil {
			return ErrLaunch
		}
		defer sys.destroyEnvironment(env)
		startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
		var process windows.ProcessInformation
		if err := sys.createProcessAsUser(primary, app, command, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, env, nil, &startup, &process); err != nil {
			return ErrLaunch
		}
		sys.closeHandle(process.Thread)
		sys.closeHandle(process.Process)
		return nil
	}}, nil
}

func openConsole(raw string) error { return openConsoleWith(system, raw) }

func openConsoleWith(sys api, raw string) error {
	target, err := forSession(sys, sys.activeConsole())
	if err != nil {
		return err
	}
	defer target.Close()
	return target.Open(raw)
}
