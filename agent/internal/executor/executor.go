// Package executor runs verified commands and captures their output.
package executor

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// Result is the outcome of running a command.
type Result struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
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

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if ctx.Err() == context.DeadlineExceeded {
		res.ExitCode = -1
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
