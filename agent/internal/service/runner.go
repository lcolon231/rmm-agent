// SPDX-License-Identifier: AGPL-3.0-only
// Package service contains the OS-independent agent runtime plus the Windows
// service integration (install/uninstall/start/stop, SCM lifecycle, and
// auto-recovery). The same runtime backs both the foreground console process
// and the Windows service, so behavior is identical either way.
package service

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/config"
	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/protocol"
	"github.com/lcolon231/rmm/agent/internal/telemetry"
	"github.com/lcolon231/rmm/agent/internal/verify"
)

// errNoCredentials means there is neither a persisted identity nor an enrollment
// token to obtain one. Retrying cannot fix this, so the runtime gives up.
var errNoCredentials = errors.New("no identity on disk and no enrollment_token in config")

// fatalError marks an error that retrying will not resolve (bad config, missing
// credentials). Network errors are left bare so the runtime retries them.
type fatalError struct{ err error }

func (e fatalError) Error() string { return e.err.Error() }
func (e fatalError) Unwrap() error { return e.err }

func fatal(err error) error {
	if err == nil {
		return nil
	}
	return fatalError{err}
}

func isFatal(err error) bool {
	var fe fatalError
	return errors.As(err, &fe)
}

// Agent is the OS-independent agent runtime: enroll once, then check in on a
// cadence, verifying and executing signed commands. It is driven either by the
// foreground console path or by the Windows service wrapper.
type Agent struct {
	configPath string
	version    string
	log        *log.Logger

	// shutdownGrace bounds how long Run waits for an in-flight command to finish
	// after a stop is requested before force-cancelling it.
	shutdownGrace time.Duration
	// backoffInitial / backoffMax bound network retry spacing.
	backoffInitial time.Duration
	backoffMax     time.Duration

	// run executes a verified command. It is a field so tests can substitute a
	// stub rather than spawning real processes; production uses executor.RunContext.
	run func(ctx context.Context, kind, script string) executor.Result
}

// NewAgent builds a runtime that reads config (and persists identity) at
// configPath and logs through logger.
func NewAgent(configPath, version string, logger *log.Logger) *Agent {
	return &Agent{
		configPath:     configPath,
		version:        version,
		log:            logger,
		shutdownGrace:  20 * time.Second,
		backoffInitial: 1 * time.Second,
		backoffMax:     5 * time.Minute,
		run:            executor.RunContext,
	}
}

// session holds the resolved per-run state after enrollment.
type session struct {
	api          *client.Client
	pub          ed25519.PublicKey
	pubKeys      map[string]ed25519.PublicKey
	identityPath string
	identity     *config.Identity
	agentID      string
	interval     time.Duration
	// seen is the persisted set of already-executed command IDs, used for replay
	// protection. Commands are processed by the single check-in goroutine, so it
	// needs no locking.
	seen *SeenStore
	// quarantined mirrors the server-reported trust state so transitions are
	// logged once instead of on every beat.
	quarantined bool
}

// Run enrolls if needed and then checks in until ctx is cancelled. On
// cancellation it stops accepting new commands and lets an in-flight command
// finish (up to shutdownGrace) before force-cancelling it, so no child process
// is left orphaned. It returns a non-nil error only for unrecoverable
// (fatal) conditions such as invalid config.
func (a *Agent) Run(ctx context.Context) error {
	// execCtx controls running child processes. It is cancelled only after the
	// shutdown grace expires, giving an in-flight command time to finish.
	execCtx, cancelExec := context.WithCancel(context.Background())
	defer cancelExec()

	errc := make(chan error, 1)
	go func() { errc <- a.loop(ctx, execCtx) }()

	select {
	case err := <-errc:
		return err // loop exited on its own (fatal error)
	case <-ctx.Done():
		a.log.Printf("shutting down")
	}

	// Grace period for an in-flight command to finish before we kill it.
	select {
	case <-errc:
	case <-time.After(a.shutdownGrace):
		a.log.Printf("shutdown grace elapsed; cancelling in-flight command")
		cancelExec()
		<-errc
	}
	return nil
}

// RunOnce performs enrollment (if needed) and a single check-in, then returns.
// It does not retry on failure — it mirrors the old -once behavior.
func (a *Agent) RunOnce(ctx context.Context) error {
	sess, err := a.loadSession(ctx)
	if err != nil {
		return err
	}
	return a.checkIn(ctx, ctx, sess)
}

// loop runs the enroll-then-check-in cycle. ctx signals shutdown; execCtx backs
// running child processes so they can outlive a stop request briefly.
func (a *Agent) loop(ctx, execCtx context.Context) error {
	b := newBackoff(a.backoffInitial, a.backoffMax, 2.0, rand.New(rand.NewSource(time.Now().UnixNano())))

	// Establish a session (loading identity or enrolling), retrying on network
	// failure so a server that is down at boot means "keep trying quietly."
	var sess *session
	for sess == nil {
		s, err := a.loadSession(ctx)
		if err != nil {
			if isFatal(err) {
				return err
			}
			wait := b.Next()
			a.log.Printf("enrollment failed (%v); retrying in %s", err, wait.Round(time.Millisecond))
			if !sleepCtx(ctx, wait) {
				return nil
			}
			continue
		}
		sess = s
	}
	b.Reset()
	a.log.Printf("check-in interval: %s", sess.interval)

	// Immediate first beat, then on the interval; back off on network failure.
	for {
		err := a.checkIn(ctx, execCtx, sess)
		var wait time.Duration
		if err != nil {
			wait = b.Next()
			if client.IsUnauthorized(err) {
				// A definitive credential rejection usually means the agent was
				// revoked server-side. Keep the identity on disk for operator
				// investigation and keep retrying at capped backoff — a server
				// restored from backup can also cause a transient 401.
				a.log.Printf("server rejected agent credentials (agent may be revoked); retrying in %s", wait.Round(time.Millisecond))
			} else {
				a.log.Printf("check-in failed (%v); retrying in %s", err, wait.Round(time.Millisecond))
			}
		} else {
			b.Reset()
			wait = sess.interval
		}
		if !sleepCtx(ctx, wait) {
			return nil
		}
	}
}

// loadSession loads config and identity, enrolling if no identity exists yet.
func (a *Agent) loadSession(ctx context.Context) (*session, error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, fatal(err) // a bad/missing config will not fix itself
	}
	idPath := config.IdentityPath(a.configPath)
	identity, err := a.ensureEnrolled(ctx, cfg, idPath)
	if err != nil {
		return nil, err
	}
	pub, err := verify.PublicKeyFromPEM(identity.CommandPublicKey)
	if err != nil {
		return nil, fatal(fmt.Errorf("command public key: %w", err))
	}
	pubKeys := map[string]ed25519.PublicKey{}
	if identity.CommandSigningKeyID != "" && len(identity.CommandPublicKeys) > 0 {
		for keyID, pemKey := range identity.CommandPublicKeys {
			parsed, parseErr := verify.PublicKeyFromPEM(pemKey)
			if parseErr != nil {
				return nil, fatal(fmt.Errorf("command public key %s: %w", keyID, parseErr))
			}
			pubKeys[keyID] = parsed
		}
	}
	interval := time.Duration(identity.HeartbeatSeconds) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}
	// Load the replay-protection store (empty if this is a first run) and prune
	// entries whose TTL has already lapsed; the TTL check would reject them anyway.
	seen, err := LoadSeenStore(SeenStorePath(a.configPath))
	if err != nil {
		return nil, fatal(fmt.Errorf("load replay store: %w", err))
	}
	seen.Prune(time.Now().UTC())
	return &session{
		api:          client.New(identity.ServerURL, identity.AgentToken),
		pub:          pub,
		pubKeys:      pubKeys,
		identityPath: idPath,
		identity:     identity,
		agentID:      identity.AgentID,
		interval:     interval,
		seen:         seen,
	}, nil
}

// ensureEnrolled returns a persisted identity, enrolling first if none exists.
// A missing/invalid config or absent credentials is fatal; a failed enroll call
// (network) is returned bare so the caller retries.
func (a *Agent) ensureEnrolled(ctx context.Context, cfg *config.Config, idPath string) (*config.Identity, error) {
	if id, err := config.LoadIdentity(idPath); err == nil {
		a.log.Printf("loaded existing identity: agent %s", id.AgentID)
		return id, nil
	} else if !os.IsNotExist(err) {
		return nil, fatal(err) // an unreadable/corrupt identity is fatal
	}

	if cfg.EnrollmentToken == "" {
		return nil, fatal(errNoCredentials)
	}

	a.log.Printf("enrolling with server %s", cfg.ServerURL)
	host := telemetry.BasicHostInfo()
	api := client.New(cfg.ServerURL, "")
	resp, err := api.Enroll(ctx, cfg.EnrollmentToken, host, a.version)
	if err != nil {
		return nil, err // network/enroll error: retryable
	}

	id := &config.Identity{
		AgentID:             resp.AgentID,
		AgentToken:          resp.AgentToken,
		CommandPublicKey:    resp.CommandPublicKey,
		CommandPublicKeys:   resp.CommandPublicKeys,
		CommandSigningKeyID: resp.CommandSigningKeyID,
		HeartbeatSeconds:    resp.HeartbeatSeconds,
		ServerURL:           cfg.ServerURL,
	}
	if err := id.Save(idPath); err != nil {
		return nil, fatal(err)
	}
	a.log.Printf("enrolled as agent %s; identity saved to %s", id.AgentID, idPath)
	return id, nil
}

// checkIn performs one heartbeat and processes any returned commands. It returns
// an error only for a failed heartbeat (which drives backoff); command failures
// are reported to the server and logged but do not fail the beat. ctx signals
// shutdown (stop accepting new commands); execCtx backs command execution.
func (a *Agent) checkIn(ctx, execCtx context.Context, s *session) error {
	// Telemetry collection may invoke platform tools (PowerShell on Windows),
	// so make cancellation visible to the collector instead of starting work
	// after shutdown has already been requested.
	if err := ctx.Err(); err != nil {
		return err
	}
	sample := telemetry.CollectContext(ctx)
	ack, err := s.api.Heartbeat(ctx, sample, nil)
	if err != nil {
		return err
	}
	// Quarantine: the server keeps answering our beats but has suspended trust.
	// Execute nothing — even if commands were somehow present in the ack — and
	// keep checking in so a restore takes effect on the next beat.
	if ack.TrustState == client.TrustStateQuarantined {
		if !s.quarantined {
			a.log.Printf("server has QUARANTINED this agent; suspending command execution until restored")
			s.quarantined = true
		}
		return nil
	}
	if s.quarantined {
		a.log.Printf("server restored this agent from quarantine; resuming normal operation")
		s.quarantined = false
	}
	if len(ack.CommandPublicKeys) > 0 {
		updated := map[string]ed25519.PublicKey{}
		for keyID, pemKey := range ack.CommandPublicKeys {
			parsed, parseErr := verify.PublicKeyFromPEM(pemKey)
			if parseErr != nil {
				return fmt.Errorf("invalid signing-key bundle entry %s: %w", keyID, parseErr)
			}
			updated[keyID] = parsed
		}
		s.pubKeys = updated
		s.identity.CommandPublicKeys = ack.CommandPublicKeys
		if err := s.identity.Save(s.identityPath); err != nil {
			a.log.Printf("failed to persist signing-key bundle: %v", err)
		}
	}
	if len(ack.PendingCommands) == 0 {
		return nil
	}
	a.log.Printf("received %d command(s)", len(ack.PendingCommands))
	for i, cmd := range ack.PendingCommands {
		a.processCommand(execCtx, s, cmd)
		// On shutdown, finish the current command but do not start new ones.
		if ctx.Err() != nil {
			if remaining := len(ack.PendingCommands) - i - 1; remaining > 0 {
				a.log.Printf("stop requested; deferring %d remaining command(s)", remaining)
			}
			break
		}
	}
	return nil
}

// processCommand runs the accept/refuse gate for one command in strict order:
// signature/shape -> signed time window -> nonce replay -> ID replay -> execute. A command that fails any gate is
// refused and never executed.
func (a *Agent) processCommand(ctx context.Context, s *session, cmd client.Command) {
	if cmd.AgentID != s.agentID {
		a.log.Printf("REFUSING command %s: agent identity mismatch", cmd.ID)
		_ = s.api.ReportResult(ctx, cmd.ID, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: agent identity mismatch",
		})
		return
	}

	var verifyErr error
	if cmd.EnvelopeVersion == protocol.CommandEnvelopeV3 {
		pub, ok := s.pubKeys[cmd.SigningKeyID]
		if !ok {
			a.log.Printf("REFUSING command %s: unknown or retired signing key %q", cmd.ID, cmd.SigningKeyID)
			_ = s.api.ReportResult(ctx, cmd.ID, client.CommandResult{ExitCode: -1, Stderr: "agent refused command: unknown signing key"})
			return
		}
		verifyErr = verify.VerifyWithKeyID(pub, cmd.EnvelopeVersion, cmd.SchemaVersion, cmd.ID, s.agentID, cmd.Kind, cmd.Payload, cmd.IssuedAt, cmd.ExpiresAt, cmd.Nonce, cmd.SigningKeyID, cmd.Signature)
	} else {
		verifyErr = verify.Verify(s.pub, cmd.EnvelopeVersion, cmd.SchemaVersion, cmd.ID, s.agentID, cmd.Kind, cmd.Payload, cmd.IssuedAt, cmd.ExpiresAt, cmd.Nonce, cmd.Signature)
	}
	if err := verifyErr; err != nil {
		a.log.Printf("REFUSING command %s: signature invalid: %v", cmd.ID, err)
		_ = s.api.ReportResult(ctx, cmd.ID, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: signature verification failed",
		})
		return
	}

	// Time window: all values are signed and required. Malformed, stale, overly
	// long-lived, or implausibly future commands fail closed.
	expiry, err := verify.ValidateCommandWindow(cmd.IssuedAt, cmd.ExpiresAt, time.Now().UTC())
	if err != nil {
		a.log.Printf("REFUSING command %s: invalid time window: %v", cmd.ID, err)
		_ = s.api.ReportResult(ctx, cmd.ID, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: invalid signed time window",
		})
		return
	}

	// Replay: an id we have already executed must not run again. We do not report
	// a result here, to avoid clobbering the original execution's result.
	if s.seen.Has(cmd.ID) {
		a.log.Printf("REFUSING command %s: already executed", cmd.ID)
		return
	}

	if s.seen.HasNonce(cmd.Nonce) {
		a.log.Printf("REFUSING command %s: nonce already used", cmd.ID)
		_ = s.api.ReportResult(ctx, cmd.ID, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: repeated nonce",
		})
		return
	}

	// Reserve both replay keys durably before starting the process. If the agent
	// cannot persist this reservation, fail closed rather than execute a command
	// that could be replayed after a restart.
	s.seen.Add(cmd.ID, expiry)
	s.seen.AddNonce(cmd.Nonce, expiry)
	if err := s.seen.Save(); err != nil {
		a.log.Printf("failed to persist replay store after %s: %v", cmd.ID, err)
		_ = s.api.ReportResult(ctx, cmd.ID, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: replay state could not be persisted",
		})
		return
	}

	script := extractScript(cmd.Payload)
	a.log.Printf("executing command %s (kind=%s)", cmd.ID, cmd.Kind)
	res := a.run(ctx, cmd.Kind, script)

	if err := s.api.ReportResult(ctx, cmd.ID, client.CommandResult{
		ExitCode: res.ExitCode,
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
	}); err != nil {
		a.log.Printf("failed to report result for %s: %v", cmd.ID, err)
	}
}

// extractScript pulls the "script" field from a command payload, if present.
func extractScript(payload json.RawMessage) string {
	var p struct {
		Script string `json:"script"`
	}
	_ = json.Unmarshal(payload, &p)
	return p.Script
}

// sleepCtx waits for d or until ctx is cancelled. It reports whether the full
// duration elapsed (true) versus being cancelled early (false).
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// LogFilePath is the fixed path the service logs to (no console attached). On
// Windows this lives under %ProgramData% so it survives user logoff.
func LogFilePath() string {
	return filepath.Join(logDir(), "rmm-agent.log")
}

func logDir() string {
	if runtime.GOOS == "windows" {
		pd := os.Getenv("ProgramData")
		if pd == "" {
			pd = `C:\ProgramData`
		}
		return filepath.Join(pd, "NodeLink", "logs")
	}
	return "/var/log/nodelink"
}

// ConfigNextToExe returns the config path beside the running executable, which
// is where the installed service reads its config from.
func ConfigNextToExe() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "config.json"), nil
}

// NewFileLogger builds a logger writing to a size-rotated file under logDir
// (10 MB per file, 5 backups). The returned Closer closes the file.
func NewFileLogger() (*log.Logger, io.Closer, error) {
	w, err := newRotatingWriter(LogFilePath(), 10*1024*1024, 5)
	if err != nil {
		return nil, nil, err
	}
	return log.New(w, "", log.LstdFlags|log.LUTC), w, nil
}
