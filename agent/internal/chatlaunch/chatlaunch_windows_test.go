//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatlaunch

import (
	"errors"
	"slices"
	"testing"

	"golang.org/x/sys/windows"
)

const (
	fakeUser    windows.Token  = 0x111
	fakePrimary windows.Token  = 0x222
	fakeThread  windows.Handle = 0x333
	fakeProcess windows.Handle = 0x444
	chatURL                    = "https://support.test/chat#c=conversation&t=secret"
)

var errFake = errors.New("fake win32 failure")

// fakeSystem records every Win32 call so tests can assert which handles were
// released and what the browser process was started with.
type fakeSystem struct {
	console      uint32
	failAt       string
	queried      []uint32
	closed       []windows.Handle
	envDestroyed bool
	token        windows.Token
	app, command string
	desktop      string
	flags        uint32
}

func (f *fakeSystem) fail(step string) error {
	if f.failAt == step {
		return errFake
	}
	return nil
}

func (f *fakeSystem) api() api {
	env := new(uint16)
	return api{
		activeConsole: func() uint32 { return f.console },
		queryUserToken: func(session uint32, token *windows.Token) error {
			f.queried = append(f.queried, session)
			*token = fakeUser
			return f.fail("query")
		},
		duplicateTokenEx: func(existing windows.Token, _ uint32, _ *windows.SecurityAttributes, level uint32, kind uint32, token *windows.Token) error {
			if existing != fakeUser || level != windows.SecurityImpersonation || kind != windows.TokenPrimary {
				return errors.New("duplicated the wrong token")
			}
			*token = fakePrimary
			return f.fail("duplicate")
		},
		closeHandle: func(h windows.Handle) error { f.closed = append(f.closed, h); return nil },
		systemDirectory: func() (string, error) {
			return `C:\Windows\System32`, f.fail("directory")
		},
		createEnvironment: func(block **uint16, token windows.Token, inherit bool) error {
			if token != fakePrimary || inherit {
				return errors.New("environment built from the wrong token")
			}
			*block = env
			return f.fail("environment")
		},
		destroyEnvironment: func(block *uint16) error { f.envDestroyed = block == env; return nil },
		createProcessAsUser: func(token windows.Token, app, command *uint16, _, _ *windows.SecurityAttributes, inherit bool, flags uint32, block, _ *uint16, startup *windows.StartupInfo, process *windows.ProcessInformation) error {
			if inherit || block != env {
				return errors.New("process inherited handles or lost its environment")
			}
			f.token, f.flags = token, flags
			f.app, f.command = windows.UTF16PtrToString(app), windows.UTF16PtrToString(command)
			f.desktop = windows.UTF16PtrToString(startup.Desktop)
			process.Thread, process.Process = fakeThread, fakeProcess
			return f.fail("process")
		},
	}
}

func TestForSessionRefusesWithoutInteractiveSession(t *testing.T) {
	tests := []struct {
		name    string
		session uint32
		failAt  string
		queried bool
	}{
		{"services session", 0, "", false},
		{"no console attached", 0xffffffff, "", false},
		{"no user logged on", 3, "query", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeSystem{failAt: tt.failAt}
			target, err := forSession(fake.api(), tt.session)
			if target != nil || err != ErrNoSession {
				t.Fatalf("forSession = %v, %v; want nil, ErrNoSession", target, err)
			}
			if got := len(fake.queried) > 0; got != tt.queried {
				t.Fatalf("queried user token = %v, want %v", got, tt.queried)
			}
		})
	}
}

func TestForSessionDuplicateFailureReleasesUserToken(t *testing.T) {
	fake := &fakeSystem{failAt: "duplicate"}
	target, err := forSession(fake.api(), 2)
	if target != nil || err != ErrLaunch {
		t.Fatalf("forSession = %v, %v; want nil, ErrLaunch", target, err)
	}
	if !slices.Equal(fake.closed, []windows.Handle{windows.Handle(fakeUser)}) {
		t.Fatalf("closed %v, want only the user token", fake.closed)
	}
}

func TestTargetLaunchesBrowserInCapturedSession(t *testing.T) {
	fake := &fakeSystem{}
	target, err := forSession(fake.api(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.queried, []uint32{7}) {
		t.Fatalf("queried sessions %v, want [7]", fake.queried)
	}
	// The impersonation token is released as soon as the primary copy exists.
	if !slices.Equal(fake.closed, []windows.Handle{windows.Handle(fakeUser)}) {
		t.Fatalf("closed %v after capture, want only the user token", fake.closed)
	}
	if err := target.Open(chatURL); err != nil {
		t.Fatal(err)
	}
	const rundll = `C:\Windows\System32\rundll32.exe`
	if fake.token != fakePrimary || fake.app != rundll || fake.desktop != `winsta0\default` {
		t.Fatalf("process token=%v app=%q desktop=%q", fake.token, fake.app, fake.desktop)
	}
	if want := rundll + " url.dll,FileProtocolHandler " + chatURL; fake.command != want {
		t.Fatalf("command line %q, want %q", fake.command, want)
	}
	if fake.flags != windows.CREATE_UNICODE_ENVIRONMENT {
		t.Fatalf("creation flags 0x%x", fake.flags)
	}
	if !fake.envDestroyed {
		t.Fatal("environment block leaked")
	}
	target.Close()
	want := []windows.Handle{windows.Handle(fakeUser), fakeThread, fakeProcess, windows.Handle(fakePrimary)}
	if !slices.Equal(fake.closed, want) {
		t.Fatalf("closed %v, want %v", fake.closed, want)
	}
}

func TestTargetLaunchFailuresReportErrLaunch(t *testing.T) {
	tests := []struct {
		failAt       string
		envDestroyed bool
	}{
		{"directory", false},
		{"environment", false},
		{"process", true},
	}
	for _, tt := range tests {
		t.Run(tt.failAt, func(t *testing.T) {
			fake := &fakeSystem{failAt: tt.failAt}
			target, err := forSession(fake.api(), 4)
			if err != nil {
				t.Fatal(err)
			}
			defer target.Close()
			if err := target.Open(chatURL); err != ErrLaunch {
				t.Fatalf("Open = %v, want ErrLaunch", err)
			}
			if fake.envDestroyed != tt.envDestroyed {
				t.Fatalf("environment destroyed = %v, want %v", fake.envDestroyed, tt.envDestroyed)
			}
			if slices.Contains(fake.closed, fakeProcess) {
				t.Fatal("closed a process handle that was never created")
			}
		})
	}
}

func TestOpenConsoleUsesActiveConsoleSession(t *testing.T) {
	fake := &fakeSystem{console: 5}
	if err := openConsoleWith(fake.api(), chatURL); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(fake.queried, []uint32{5}) || fake.command == "" {
		t.Fatalf("queried %v, command %q", fake.queried, fake.command)
	}
	if !slices.Contains(fake.closed, windows.Handle(fakePrimary)) {
		t.Fatal("primary token not released after a one-shot open")
	}

	fake = &fakeSystem{console: 0xffffffff}
	if err := openConsoleWith(fake.api(), chatURL); err != ErrNoSession {
		t.Fatalf("openConsoleWith = %v, want ErrNoSession", err)
	}

	fake = &fakeSystem{console: 5}
	if err := openConsoleWith(fake.api(), "http://support.test/chat#x"); err != ErrURL || fake.command != "" {
		t.Fatalf("unsafe URL: err=%v command=%q", err, fake.command)
	}
}
