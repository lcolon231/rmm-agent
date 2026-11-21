// SPDX-License-Identifier: AGPL-3.0-only

// Package pwshtest provides the fake pwsh.Runner every package's tests drive
// their PowerShell glue with, so parsers and script builders run on every OS
// without a live system.
package pwshtest

import (
	"context"
	"sync"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// Fake records each Script it is asked to run and answers with Reply, or with
// an empty successful Result when Reply is nil.
type Fake struct {
	Reply func(pwsh.Script) (pwsh.Result, error)

	mu    sync.Mutex
	calls []pwsh.Script
}

// Run is the pwsh.Runner; pass f.Run where a package expects one.
func (f *Fake) Run(_ context.Context, s pwsh.Script) (pwsh.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	reply := f.Reply
	f.mu.Unlock()
	if reply == nil {
		return pwsh.Result{}, nil
	}
	return reply(s)
}

// Calls returns the Scripts run so far, in order.
func (f *Fake) Calls() []pwsh.Script {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]pwsh.Script(nil), f.calls...)
}

// Stdout is a Reply for a run that printed out and exited 0.
func Stdout(out string) func(pwsh.Script) (pwsh.Result, error) {
	return func(pwsh.Script) (pwsh.Result, error) {
		return pwsh.Result{Stdout: []byte(out)}, nil
	}
}

// Exit is a Reply for a run that printed stdout and stderr and exited with
// code, failing with *pwsh.ExitError when code is non-zero.
func Exit(stdout, stderr string, code int) func(pwsh.Script) (pwsh.Result, error) {
	return func(pwsh.Script) (pwsh.Result, error) {
		res := pwsh.Result{Stdout: []byte(stdout), Stderr: []byte(stderr), ExitCode: code}
		if code != 0 {
			return res, &pwsh.ExitError{Code: code}
		}
		return res, nil
	}
}

// Fail is a Reply for a run that could not complete at all, such as a timeout.
func Fail(err error) func(pwsh.Script) (pwsh.Result, error) {
	return func(pwsh.Script) (pwsh.Result, error) {
		return pwsh.Result{ExitCode: -1}, err
	}
}
