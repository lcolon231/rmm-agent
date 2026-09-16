//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatlaunch

import (
	"golang.org/x/sys/windows"
	"path/filepath"
	"unsafe"
)

func ForSession(session uint32) (*Target, error) {
	if session == 0 || session == 0xffffffff {
		return nil, ErrNoSession
	}
	var user windows.Token
	if err := windows.WTSQueryUserToken(session, &user); err != nil {
		return nil, ErrNoSession
	}
	defer user.Close()
	var primary windows.Token
	if err := windows.DuplicateTokenEx(user, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &primary); err != nil {
		return nil, ErrLaunch
	}
	return &Target{release: func() { primary.Close() }, launch: func(raw string) error {
		directory, err := windows.GetSystemDirectory()
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
		if err := windows.CreateEnvironmentBlock(&env, primary, false); err != nil {
			return ErrLaunch
		}
		defer windows.DestroyEnvironmentBlock(env)
		startup := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
		var process windows.ProcessInformation
		if err := windows.CreateProcessAsUser(primary, app, command, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, env, nil, &startup, &process); err != nil {
			return ErrLaunch
		}
		windows.CloseHandle(process.Thread)
		windows.CloseHandle(process.Process)
		return nil
	}}, nil
}

func openConsole(raw string) error {
	target, err := ForSession(windows.WTSGetActiveConsoleSessionId())
	if err != nil {
		return err
	}
	defer target.Close()
	return target.Open(raw)
}
