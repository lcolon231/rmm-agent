// SPDX-License-Identifier: AGPL-3.0-only

// Package pwsh is the agent's one way to run a Windows PowerShell script.
//
// Every run through Exec uses the same hardened flag set, the same timeout and
// kill handling, and keeps stdout and stderr apart. The executor, which runs
// operator scripts under its own Job Object, shares only the flag set through
// Args and StdinArgs. Caller data never enters the
// script text: a Script's Env entries reach the child as environment variables
// the body reads as $env:NAME, so a hostile service name or file path cannot
// change what PowerShell runs.
//
// Packages take a Runner so their parsers and script builders are testable on
// every OS. Production code passes Exec; tests pass a pwshtest.Fake.
package pwsh

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
)

// Exe is the Windows PowerShell 5.1 binary, present on every supported Windows.
const Exe = "powershell.exe"

// flags precede every invocation. -NoProfile keeps a user or machine profile
// from running inside the agent's privileged process; -NonInteractive turns a
// prompt into an error instead of a hang; -ExecutionPolicy Bypass applies only
// to this process and stops a locally restrictive policy from refusing the
// signed modules the scripts auto-load (a Group Policy setting still wins).
var flags = []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"}

// Script is one PowerShell invocation.
type Script struct {
	// Body is the script text. It must be a constant or built only from
	// constants; caller data goes in Env.
	Body string
	// Env holds named arguments, exposed to Body as $env:NAME.
	Env map[string]string
	// Timeout bounds the run. Exec refuses a zero timeout.
	Timeout time.Duration
	// Encoded passes Body as -EncodedCommand (UTF-16LE base64) instead of
	// -Command, which sidesteps command-line quoting for large multi-line
	// scripts such as the Windows Update installer.
	Encoded bool
}

// Result is what a finished process wrote and how it exited.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs a Script. A run that completed with exit code 0 returns a nil
// error. A non-zero exit returns *ExitError, a timeout ErrTimeout, and a
// cancelled parent context its error; in each case Result holds whatever the
// process wrote before it stopped.
type Runner func(ctx context.Context, s Script) (Result, error)

// ErrTimeout reports that a run outlived its Script.Timeout and was killed.
var ErrTimeout = errors.New("powershell timed out")

// ExitError reports a process that ran and exited non-zero.
type ExitError struct{ Code int }

// Error matches os/exec's wording so existing operator-facing messages keep
// their shape.
func (e *ExitError) Error() string { return fmt.Sprintf("exit status %d", e.Code) }

// Args returns the argv after Exe for s.
func Args(s Script) []string {
	args := append([]string(nil), flags...)
	if s.Encoded {
		return append(args, "-EncodedCommand", encodeUTF16LE(s.Body))
	}
	return append(args, "-Command", s.Body)
}

// StdinArgs returns the argv after Exe for a session that reads its commands
// from standard input, as the interactive shell does.
func StdinArgs() []string {
	return append(append([]string(nil), flags...), "-Command", "-")
}

// Environ returns base with any inherited PSModulePath removed and env
// appended in name order.
//
// PSModulePath is dropped because an agent started from PowerShell 7 inherits
// one pointing at PowerShell 7's modules, and the Windows PowerShell child then
// fails to load its own (CimCmdlets, Microsoft.PowerShell.Security). Without
// it, powershell.exe rebuilds its default.
func Environ(base []string, env map[string]string) ([]string, error) {
	names := make([]string, 0, len(env))
	for name, value := range env {
		if !validName(name) {
			return nil, fmt.Errorf("invalid powershell argument name %q", name)
		}
		if strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("powershell argument %s contains a NUL byte", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]string, 0, len(base)+len(names))
	for _, kv := range base {
		if isPSModulePath(kv) {
			continue
		}
		out = append(out, kv)
	}
	for _, name := range names {
		out = append(out, name+"="+env[name])
	}
	return out, nil
}

func isPSModulePath(kv string) bool {
	const key = "PSModulePath="
	return len(kv) >= len(key) && strings.EqualFold(kv[:len(key)], key)
}

// validName accepts a PowerShell-addressable identifier, so "$env:NAME" in the
// body reads exactly this variable and the name cannot carry an "=" of its own.
func validName(name string) bool {
	if name == "" || strings.EqualFold(name, "PSModulePath") {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// encodeUTF16LE encodes s for -EncodedCommand, which takes the base64 of the
// script's UTF-16LE bytes.
func encodeUTF16LE(s string) string {
	encoded := utf16.Encode([]rune(s))
	buf := make([]byte, len(encoded)*2)
	for i, u := range encoded {
		buf[i*2] = byte(u)
		buf[i*2+1] = byte(u >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
