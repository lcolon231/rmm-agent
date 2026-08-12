// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/executor"
)

const shellAttachInterval = time.Second

// shellSessionLoop discovers operator-opened sessions independently of the
// heartbeat cadence. It never logs frame data and backs off quietly when no
// session exists or the server is temporarily unavailable.
func (a *Agent) shellSessionLoop(ctx context.Context, s *session) {
	for ctx.Err() == nil {
		session, err := s.api.AttachShellSession(ctx)
		if err != nil {
			if ctx.Err() == nil {
				a.log.Printf("interactive shell attach failed: %v", err)
			}
			if !sleepCtx(ctx, shellAttachInterval) {
				return
			}
			continue
		}
		if session == nil {
			if !sleepCtx(ctx, shellAttachInterval) {
				return
			}
			continue
		}

		s.executionMu.Lock()
		err = a.runShellSession(ctx, s, session)
		s.executionMu.Unlock()
		if err != nil && ctx.Err() == nil {
			a.log.Printf("interactive shell %s ended: %v", session.ID, err)
		}
	}
}

type shellInputResult struct {
	frames []client.ShellFrame
	err    error
}

func (a *Agent) runShellSession(parent context.Context, s *session, session *client.ShellSession) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	input := make(chan []byte, 8)
	output := make(chan executor.InteractiveChunk, 8)
	processDone := make(chan error, 1)
	go func() { processDone <- executor.RunInteractive(ctx, input, output) }()

	inputResults := make(chan shellInputResult, 1)
	go a.pollShellInput(ctx, s, session.ID, input, inputResults)

	var outputSeq = session.AgentLastSeq
	finishState := "closed"
	finishReason := "shell_exited"
	for {
		select {
		case chunk := <-output:
			outputSeq++
			frame := client.ShellFrame{
				Seq:        outputSeq,
				Stream:     chunk.Stream,
				DataBase64: base64.StdEncoding.EncodeToString(chunk.Data),
			}
			if err := sendShellOutputWithRetry(ctx, s.api, session.ID, frame); err != nil {
				finishState = "failed"
				finishReason = shellFailureReason(err)
				cancel()
				drainShellProcess(output, processDone)
				completeCtx, completeCancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = s.api.CompleteShellSession(completeCtx, session.ID, finishState, finishReason)
				completeCancel()
				return err
			}
		case result := <-inputResults:
			if result.err != nil {
				finishState = "failed"
				finishReason = shellFailureReason(result.err)
				cancel()
				drainShellProcess(output, processDone)
				completeCtx, completeCancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = s.api.CompleteShellSession(completeCtx, session.ID, finishState, finishReason)
				completeCancel()
				return result.err
			}
		case err := <-processDone:
			// Readers enqueue every chunk before RunInteractive returns. Drain the
			// bounded channel so the final bytes reach the operator.
			draining := true
			for draining {
				select {
				case chunk := <-output:
					outputSeq++
					frame := client.ShellFrame{Seq: outputSeq, Stream: chunk.Stream, DataBase64: base64.StdEncoding.EncodeToString(chunk.Data)}
					if sendErr := sendShellOutputWithRetry(ctx, s.api, session.ID, frame); sendErr != nil {
						err = sendErr
						finishState = "failed"
						finishReason = shellFailureReason(sendErr)
						draining = false
					}
				default:
					draining = false
				}
			}
			if err != nil && !errors.Is(err, context.Canceled) {
				finishState = "failed"
				finishReason = "process_failed"
			}
			completeCtx, completeCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer completeCancel()
			if completeErr := s.api.CompleteShellSession(completeCtx, session.ID, finishState, finishReason); completeErr != nil {
				return fmt.Errorf("complete shell session: %w", completeErr)
			}
			return err
		case <-parent.Done():
			cancel()
			<-processDone
			return parent.Err()
		}
	}
}

// Cancellation can race with stdout/stderr readers that are already trying to
// publish bounded chunks. Keep draining until runCommand and both readers exit
// so a full local output channel cannot deadlock shutdown.
func drainShellProcess(output <-chan executor.InteractiveChunk, done <-chan error) {
	for {
		select {
		case <-output:
		case <-done:
			return
		}
	}
}

func (a *Agent) pollShellInput(
	ctx context.Context,
	s *session,
	sessionID string,
	input chan<- []byte,
	result chan<- shellInputResult,
) {
	defer close(input)
	var after, ack int64
	for ctx.Err() == nil {
		batch, err := s.api.PollShellInput(ctx, sessionID, after, ack)
		if err != nil {
			if shellTransportRetryable(err) && sleepCtx(ctx, time.Second) {
				continue
			}
			result <- shellInputResult{err: err}
			return
		}
		for _, frame := range batch.Frames {
			if frame.Seq != after+1 {
				result <- shellInputResult{err: fmt.Errorf("shell input sequence mismatch")}
				return
			}
			after = frame.Seq
			decoded, decodeErr := base64.StdEncoding.DecodeString(frame.DataBase64)
			if decodeErr != nil {
				result <- shellInputResult{err: fmt.Errorf("decode shell input: %w", decodeErr)}
				return
			}
			if frame.Stream == "control" || frame.EOF {
				result <- shellInputResult{frames: batch.Frames}
				return
			}
			select {
			case input <- decoded:
				ack = frame.Seq
			case <-ctx.Done():
				return
			}
		}
	}
}

func sendShellOutputWithRetry(ctx context.Context, api *client.Client, sessionID string, frame client.ShellFrame) error {
	for {
		err := api.SendShellOutput(ctx, sessionID, frame)
		if err == nil {
			return nil
		}
		if !shellTransportRetryable(err) {
			return err
		}
		if !sleepCtx(ctx, time.Second) {
			return ctx.Err()
		}
	}
}

func shellTransportRetryable(err error) bool {
	var statusErr *client.StatusError
	if !errors.As(err, &statusErr) {
		// Network interruption, timeout, or temporary DNS/TLS failure. The
		// caller keeps its exact sequence and retries the same operation.
		return true
	}
	return statusErr.StatusCode == http.StatusTooManyRequests || statusErr.StatusCode >= 500
}

func shellFailureReason(err error) string {
	var statusErr *client.StatusError
	if errors.As(err, &statusErr) {
		switch statusErr.StatusCode {
		case http.StatusRequestEntityTooLarge:
			return "output_limit"
		case http.StatusUnauthorized, http.StatusForbidden:
			return "authorization_lost"
		case http.StatusConflict:
			if strings.Contains(statusErr.Message, "not_live") {
				return "session_closed"
			}
			return "sequence_conflict"
		}
	}
	return "transport_failed"
}
