// SPDX-License-Identifier: AGPL-3.0-only
// Package executor runs verified commands and captures their output.
package executor

import (
	"context"
	"io"
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

// Kind mirrors the server's CommandKind values.
const (
	KindPowerShell = "powershell"
	KindShell      = "shell"
	KindInventory  = "collect_inventory"
	// KindScanUpdates is a typed operation handled by the runner, not this
	// script executor: it triggers a bounded Windows Update scan (issue #51).
	KindScanUpdates = "scan_updates"
	// KindInstallUpdates triggers selective installation of Windows updates.
	KindInstallUpdates      = "install_updates"
	KindFileUpload          = "file_upload"
	KindFileDownload        = "file_download"
	KindRegistryRead        = "registry_read"
	KindRegistryWrite       = "registry_write"
	KindRegistryDelete      = "registry_delete"
	KindRemediationRollback = "remediation_rollback"
	KindReboot              = "reboot"
	KindShutdown            = "shutdown"
	KindCancelPowerAction   = "cancel_power_action"
	// KindQueryEventLog runs a bounded, metadata-only Windows event log query
	// (issue #58). It never returns message text or EventData.
	KindQueryEventLog = "query_event_log"
	// KindScanPackages triggers a bounded package-manager discovery (issue #55):
	// installed packages and available upgrades from the enabled provider(s). Like
	// scan_updates it is a read-only typed operation whose normalized result lands
	// in the installed_packages inventory section.
	KindScanPackages = "scan_packages"
	// KindInstallPackages installs or upgrades an explicit, bounded set of packages
	// via a chosen provider (winget, or opt-in chocolatey). It never accepts script
	// text and re-validates the signed provider evidence at the endpoint.
	KindInstallPackages = "install_packages"
	// KindDeploySoftware downloads an MSI/EXE installer over HTTPS, verifies its
	// SHA-256 (and optional Authenticode signer), runs it with a bounded argument
	// policy and timeout, maps the exit code, and applies a reboot policy (issue
	// #56). It never accepts script text.
	KindDeploySoftware = "deploy_software"
	// Windows service and process management (issue #57). Listing is read-only;
	// control/terminate are validated, confirmed, protected-target-guarded typed
	// operations that never accept script text.
	KindListServices     = "list_services"
	KindControlService   = "control_service"
	KindListProcesses    = "list_processes"
	KindTerminateProcess = "terminate_process"
	// Signed, staged agent self-update and rollback (issue #63). The signed
	// payload carries the release metadata (version, channel, artifact digest,
	// anti-rollback floor); the agent verifies the artifact, stages it, replaces
	// itself atomically, restarts, health-checks the new build, and restores the
	// retained previous build automatically when the check fails. Neither kind
	// ever accepts script text.
	KindAgentSelfUpdate     = "agent_self_update"
	KindAgentUpdateRollback = "agent_update_rollback"
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
	return RunContextWithParameters(parent, kind, script, nil)
}

// RunContextWithParameters binds typed values to generated NL_PARAM_* shell
// variables before execution and redacts declared secrets from both streams.
// The legacy signed command schema does not call this yet; the future library
// dispatch contract must negotiate support before supplying parameters.
func RunContextWithParameters(parent context.Context, kind string, script string, parameters []ParameterValue) Result {
	prepared, err := RenderParameterizedScript(kind, script, parameters)
	if err != nil {
		return Result{ExitCode: -1, Stderr: "invalid script parameters: " + err.Error()}
	}
	result := runPreparedContext(parent, kind, prepared)
	result.Stdout = RedactParameterSecrets(result.Stdout, parameters)
	result.Stderr = RedactParameterSecrets(result.Stderr, parameters)
	return result
}

func runPreparedContext(parent context.Context, kind string, script string) Result {
	ctx, cancel := context.WithTimeout(parent, defaultTimeout)
	defer cancel()

	cmd := buildCommand(kind, script)
	if cmd == nil {
		return Result{ExitCode: -1, Stderr: "unsupported command kind: " + kind}
	}

	stdout := &limitWriter{max: MaxStreamBytes}
	stderr := &limitWriter{max: MaxStreamBytes}
	stdoutRead, stdoutWrite, err := os.Pipe()
	if err != nil {
		return Result{ExitCode: -1, Stderr: "create stdout capture pipe: " + err.Error()}
	}
	defer stdoutRead.Close()
	defer stdoutWrite.Close()
	stderrRead, stderrWrite, err := os.Pipe()
	if err != nil {
		return Result{ExitCode: -1, Stderr: "create stderr capture pipe: " + err.Error()}
	}
	defer stderrRead.Close()
	defer stderrWrite.Close()
	cmd.Stdout = stdoutWrite
	cmd.Stderr = stderrWrite

	stdoutDone := make(chan struct{})
	stderrDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(stdout, stdoutRead)
		close(stdoutDone)
	}()
	go func() {
		_, _ = io.Copy(stderr, stderrRead)
		close(stderrDone)
	}()

	err = runCommand(ctx, cmd)
	// The parent copies are no longer needed. Platform runners terminate the
	// command's process tree before returning, so these closes produce EOF for
	// both capture goroutines even when a script attempted deferred work.
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	<-stdoutDone
	<-stderrDone
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
	if ctx.Err() == context.Canceled {
		res.ExitCode = -1
		res.Stderr += "\n[command cancelled]"
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
