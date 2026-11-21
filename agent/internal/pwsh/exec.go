// SPDX-License-Identifier: AGPL-3.0-only
package pwsh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// waitDelay bounds how long Exec waits for the output pipes to close after the
// process exits or is killed. A grandchild that inherited them would otherwise
// hold Wait open past the timeout.
const waitDelay = 5 * time.Second

// Exec is the Runner that starts the real powershell.exe. It compiles on every
// OS so callers need no build tags; it only succeeds on Windows.
func Exec(ctx context.Context, s Script) (Result, error) {
	if s.Timeout <= 0 {
		return Result{ExitCode: -1}, errors.New("powershell script has no timeout")
	}
	bounded, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()

	cmd := exec.CommandContext(bounded, Exe, Args(s)...)
	env, err := Environ(cmd.Environ(), s.Env)
	if err != nil {
		return Result{ExitCode: -1}, err
	}
	cmd.Env = env
	cmd.WaitDelay = waitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	res := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes()}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		res.ExitCode = -1
	}

	if runErr == nil {
		// A clean exit stands even if the deadline passed while Run returned.
		return res, nil
	}
	// Check the contexts before the exit status: a killed process also exits
	// non-zero, and the caller needs to know why it stopped.
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	if bounded.Err() != nil {
		return res, fmt.Errorf("%w after %s", ErrTimeout, s.Timeout)
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		return res, &ExitError{Code: res.ExitCode}
	}
	return res, fmt.Errorf("run powershell: %w", runErr)
}
