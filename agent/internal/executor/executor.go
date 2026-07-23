// SPDX-License-Identifier: AGPL-3.0-only
// Package executor runs verified commands and captures their output.
package executor

import (
	"context"
	"os"
	"os/exec"
	"time"
)

// Result is the outcome of running a command. Output is bounded (see
// limits.go); when a stream was cut, its truncated flag is set and the total
// field reports how many bytes the child actually produced, so the operator
// can tell "complete output" from "first N bytes of more".
type Result struct {
	ExitCode         int    `json:"exit_code"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	StdoutTruncated  bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool   `json:"stderr_truncated,omitempty"`
	StdoutTotalBytes int64  `json:"stdout_total_bytes,omitempty"`
	StderrTotalBytes int64  `json:"stderr_total_bytes,omitempty"`
}

// containment binds a running command and any processes it spawns so they can
// all be terminated together. The Windows implementation is a Job Object with
// kill-on-close; other platforms put the command in its own process group and
// signal the whole group. See executor_contain_*.go.
type containment interface {
	// prepare configures cmd before it starts (e.g. a new process group on
	// POSIX). Called once, before cmd.Start.
	prepare(cmd *exec.Cmd)
	// assign places p — and its descendants — under containment. Called
	// immediately after the process starts.
	assign(p *os.Process) error
	// terminate kills the contained process tree/group.
	terminate()
	// release frees containment resources. On Windows this also kills any
	// surviving processes (kill-on-close), so it is a safe cleanup backstop.
	release()
}

// Kind mirrors the server's CommandKind values.
const (
	KindPowerShell = "powershell"
	KindShell      = "shell"
	KindInventory  = "collect_inventory"
)

// defaultTimeout bounds how long any single command may run.
const defaultTimeout = 5 * time.Minute

// Run executes a command of the given kind with the given payload. The payload
// shape depends on kind: powershell/shell expect {"script": "..."}.
func Run(kind string, script string) Result {
	return RunContext(context.Background(), kind, script)
}

// RunContext is like Run but honors a caller-supplied context in addition to the
// per-command timeout. Cancelling ctx (e.g. on service shutdown) terminates the
// child process rather than orphaning it. The defaultTimeout still bounds the
// maximum runtime.
func RunContext(parent context.Context, kind string, script string) Result {
	ctx, cancel := context.WithTimeout(parent, defaultTimeout)
	defer cancel()

	cmd := buildCommand(ctx, kind, script)
	if cmd == nil {
		return Result{ExitCode: -1, Stderr: "unsupported command kind: " + kind}
	}

	stdout := &limitWriter{max: MaxStreamBytes}
	stderr := &limitWriter{max: MaxStreamBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Contain the command and any descendants so a timeout, cancellation, or
	// service stop takes down the whole process tree rather than orphaning
	// grandchildren (issue #113). On Windows this is a Job Object with
	// kill-on-close; on other platforms it is a no-op and exec.CommandContext
	// still terminates the direct child.
	jail, err := newContainment()
	if err != nil {
		return Result{ExitCode: -1, Stderr: "process containment setup failed: " + err.Error()}
	}
	defer jail.release()
	jail.prepare(cmd)

	if err := cmd.Start(); err != nil {
		return Result{ExitCode: -1, Stderr: err.Error()}
	}
	if err := jail.assign(cmd.Process); err != nil {
		// Could not contain the tree; kill the direct child rather than risk
		// leaking it, and report the failure.
		_ = cmd.Process.Kill()
		return Result{ExitCode: -1, Stderr: "process containment failed: " + err.Error()}
	}

	// Tear the tree down when the context ends (timeout, shutdown, or an
	// explicit cancel). The watcher goroutine exits when the command completes.
	waitDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			jail.terminate()
		case <-waitDone:
		}
	}()

	err = cmd.Wait()
	close(waitDone)
	outStr, errStr, outTrunc, errTrunc := applyOutputLimits(stdout, stderr)
	res := Result{
		Stdout:           outStr,
		Stderr:           errStr,
		StdoutTruncated:  outTrunc,
		StderrTruncated:  errTrunc,
		StdoutTotalBytes: stdout.total,
		StderrTotalBytes: stderr.total,
	}
	if ctx.Err() == context.DeadlineExceeded {
		res.ExitCode = -1
		// Appended after capping: the marker must survive truncation so the
		// operator always sees why the run ended.
		res.Stderr += "\n[command timed out]"
		return res
	}
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else {
			res.ExitCode = -1
			if res.Stderr == "" {
				res.Stderr = err.Error()
			}
		}
		return res
	}
	res.ExitCode = 0
	return res
}
