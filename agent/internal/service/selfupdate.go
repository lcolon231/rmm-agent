// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/selfupdate"
	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

// executablePath is a seam so tests can point self-update at a temporary file
// instead of the test binary.
var executablePath = os.Executable

// selfUpdateOptions resolves the runtime context self-update needs: which
// binary is running, which build it is, which platform artifact this endpoint
// accepts, and which channel it follows.
func (a *Agent) selfUpdateOptions(s *session) (selfupdate.Options, error) {
	exe, err := executablePath()
	if err != nil {
		return selfupdate.Options{}, fmt.Errorf("resolve agent executable: %w", err)
	}
	return selfupdate.Options{
		CurrentVersion: a.version,
		ExePath:        exe,
		Platform:       runtime.GOOS + "/" + runtime.GOARCH,
		Channel:        s.updateChannel,
	}, nil
}

// runSelfUpdate executes one agent_self_update or agent_update_rollback command.
func (a *Agent) runSelfUpdate(
	ctx context.Context,
	s *session,
	commandID, kind string,
	payload json.RawMessage,
) executor.Result {
	opts, err := a.selfUpdateOptions(s)
	if err != nil {
		out, _ := json.Marshal(selfupdate.Result{
			Status:  selfupdate.StatusInvalid,
			Reason:  "endpoint_state_unusable",
			Message: err.Error(),
		})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: err.Error()}
	}
	return selfupdate.Execute(ctx, commandID, kind, payload, opts)
}

// resolveSelfUpdate runs once per start, before the check-in loop begins. It
// decides the fate of an attempt that a previous process staged: commit the new
// build when it comes up healthy, restore the retained previous build when it
// does not, and report either outcome so a bad release can be halted fleet-wide.
//
// A reporting failure is deliberately not fatal and does not clear the journal:
// the outcome stays on disk and is reported on a later start.
func (a *Agent) resolveSelfUpdate(ctx context.Context, s *session) {
	opts, err := a.selfUpdateOptions(s)
	if err != nil {
		a.log.Printf("self-update recovery unavailable: %v", err)
		return
	}
	outcome, err := selfupdate.Resolve(ctx, opts, func(hctx context.Context) error {
		// Health is defined as a completed authenticated check-in: the new build
		// started, read its config and protected identity, and the server
		// accepted its credentials. Anything less is not a working agent.
		_, herr := s.api.Heartbeat(hctx, telemetry.CollectContext(hctx), nil)
		return herr
	})
	if err != nil {
		a.log.Printf("self-update recovery failed: %v", err)
		return
	}
	if outcome == nil {
		return
	}
	a.log.Printf(
		"self-update attempt resolved: status=%s reason=%s from=%s to=%s running=%s",
		outcome.Status, outcome.Reason, outcome.FromVersion, outcome.ToVersion, outcome.ObservedVersion,
	)
	if err := s.api.ReportSelfUpdate(ctx, client.SelfUpdateOutcome{
		ReleaseID:       outcome.ReleaseID,
		CommandID:       outcome.CommandID,
		FromVersion:     outcome.FromVersion,
		ToVersion:       outcome.ToVersion,
		ObservedVersion: outcome.ObservedVersion,
		Status:          outcome.Status,
		Reason:          outcome.Reason,
		Attempts:        outcome.Attempts,
	}); err != nil {
		a.log.Printf("self-update outcome not yet reported (retained for retry): %v", err)
		return
	}
	if err := selfupdate.Acknowledge(opts); err != nil {
		a.log.Printf("self-update journal could not be cleared after reporting: %v", err)
	}
}
