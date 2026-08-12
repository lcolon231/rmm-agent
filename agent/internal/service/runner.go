// SPDX-License-Identifier: AGPL-3.0-only
// Package service contains the OS-independent agent runtime plus the Windows
// service integration (install/uninstall/start/stop, SCM lifecycle, and
// auto-recovery). The same runtime backs both the foreground console process
// and the Windows service, so behavior is identical either way.
package service

import (
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/config"
	"github.com/lcolon231/rmm/agent/internal/deploy"
	"github.com/lcolon231/rmm/agent/internal/eventlog"
	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/inventory"
	"github.com/lcolon231/rmm/agent/internal/monitoring"
	"github.com/lcolon231/rmm/agent/internal/packages"
	"github.com/lcolon231/rmm/agent/internal/patching"
	"github.com/lcolon231/rmm/agent/internal/power"
	"github.com/lcolon231/rmm/agent/internal/protocol"
	"github.com/lcolon231/rmm/agent/internal/remediation"
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

// EnrollIdentity performs one explicit enrollment and persists the resulting
// identity. It deliberately does not retry: if the server consumed a
// single-use token but the response was lost, the operator must inspect the
// inventory and issue a replacement rather than risk ambiguous identity.
func EnrollIdentity(
	ctx context.Context,
	serverURL, token, agentName, configPath, version string,
) (*config.Identity, error) {
	idPath := config.IdentityPath(configPath)
	if _, err := os.Stat(idPath); err == nil {
		return nil, fmt.Errorf("identity already exists at %s; revoke or remove it before re-enrolling", idPath)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect identity %s: %w", idPath, err)
	}
	host := telemetry.BasicHostInfo()
	resp, err := client.New(serverURL, "").EnrollWithName(ctx, token, agentName, host, version)
	if err != nil {
		return nil, err
	}
	id := &config.Identity{
		AgentID:              resp.AgentID,
		AgentToken:           resp.AgentToken,
		CommandPublicKey:     resp.CommandPublicKey,
		CommandPublicKeys:    resp.CommandPublicKeys,
		CommandSigningKeyID:  resp.CommandSigningKeyID,
		HeartbeatSeconds:     resp.HeartbeatSeconds,
		ServerURL:            serverURL,
		CredentialExpiresAt:  resp.CredentialExpiresAt,
		CredentialObtainedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := id.Save(idPath); err != nil {
		return nil, fmt.Errorf("persist enrolled identity: %w", err)
	}
	return id, nil
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
	// inventorySections is the last collected hardware snapshot. It is kept in
	// memory only: on restart the agent recollects and re-advertises, and the
	// server's content-hash comparison means an unchanged machine still uploads
	// nothing. Persisting it would add a cache to keep coherent for no gain.
	inventorySections []inventory.Section
	monitoringStore   *monitoring.Store
	monitoringEval    *monitoring.Evaluator
	// packagesConfig carries the endpoint's opt-in package-provider settings
	// (issue #55) so a Chocolatey command fails closed unless enabled here.
	packagesConfig packages.Config
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
			if isFatal(err) {
				return err
			}
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
	if cfg.EnrollmentToken != "" {
		if err := config.ClearEnrollmentToken(a.configPath, cfg); err != nil {
			return nil, fatal(fmt.Errorf("remove consumed enrollment token from config: %w", err))
		}
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
	released, unknown, err := seen.RecoverInterrupted()
	if err != nil {
		return nil, fatal(fmt.Errorf("recover command journal: %w", err))
	}
	if released > 0 {
		a.log.Printf("recovered %d command reservation(s) that never started; awaiting safe server redelivery", released)
	}
	if unknown > 0 {
		a.log.Printf("recovered %d interrupted command(s) with unknown outcome; queued failure results without replay", unknown)
	}
	if seen.Prune(time.Now().UTC()) {
		if err := seen.Save(); err != nil {
			return nil, fatal(fmt.Errorf("persist pruned command journal: %w", err))
		}
	}
	api, err := client.NewWithTLSSPKIPins(
		identity.ServerURL,
		identity.AgentToken,
		cfg.TLSSPKIPins,
	)
	if err != nil {
		return nil, fatal(fmt.Errorf("agent HTTP client: %w", err))
	}
	// Report the running build on every beat (issue #179). An in-place upgrade
	// keeps the same identity and credentials, so the heartbeat is the only
	// signal that tells the server the stored enrollment-time version is stale.
	api.SetAgentVersion(a.version)
	// Advertise the Chocolatey capability only when this endpoint opted in
	// (issue #55) so the server never dispatches a Chocolatey install to an
	// agent that has not enabled it.
	api.SetCapabilities(protocol.SupportedCapabilitiesWith(cfg.Packages.ChocolateyEnabled))
	monitoringStore, err := monitoring.LoadStore(monitoring.StatePath(a.configPath))
	if err != nil {
		return nil, fatal(err)
	}
	return &session{
		api:             api,
		pub:             pub,
		pubKeys:         pubKeys,
		identityPath:    idPath,
		identity:        identity,
		agentID:         identity.AgentID,
		interval:        interval,
		seen:            seen,
		monitoringStore: monitoringStore,
		monitoringEval:  monitoring.NewEvaluator(monitoringStore, nil),
		packagesConfig: packages.Config{
			ChocolateyEnabled: cfg.Packages.ChocolateyEnabled,
			ChocolateySources: cfg.Packages.ChocolateySources,
		},
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
	api, err := client.NewWithTLSSPKIPins(cfg.ServerURL, "", cfg.TLSSPKIPins)
	if err != nil {
		return nil, fatal(fmt.Errorf("agent HTTP client: %w", err))
	}
	resp, err := api.Enroll(ctx, cfg.EnrollmentToken, host, a.version)
	if err != nil {
		return nil, err // network/enroll error: retryable
	}

	id := &config.Identity{
		AgentID:              resp.AgentID,
		AgentToken:           resp.AgentToken,
		CommandPublicKey:     resp.CommandPublicKey,
		CommandPublicKeys:    resp.CommandPublicKeys,
		CommandSigningKeyID:  resp.CommandSigningKeyID,
		HeartbeatSeconds:     resp.HeartbeatSeconds,
		ServerURL:            cfg.ServerURL,
		CredentialExpiresAt:  resp.CredentialExpiresAt,
		CredentialObtainedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := id.Save(idPath); err != nil {
		return nil, fatal(err)
	}
	if err := config.ClearEnrollmentToken(a.configPath, cfg); err != nil {
		return nil, fatal(fmt.Errorf("remove consumed enrollment token from config: %w", err))
	}
	a.log.Printf("enrolled as agent %s; identity saved to %s", id.AgentID, idPath)
	return id, nil
}

// submitInventory uploads the requested sections. The server validates and
// bounds each one and rejects the whole submission rather than storing a
// truncated copy, so a rejection means the two sides disagree about the
// contract — worth surfacing rather than silently retrying forever.
func (a *Agent) submitInventory(ctx context.Context, s *session, requested []string) error {
	sections := inventory.Select(s.inventorySections, requested)
	if len(sections) == 0 {
		return nil
	}
	ack, err := s.api.SubmitInventory(ctx, inventory.Submission{
		InventorySchemaVersion: inventory.SchemaVersion,
		AgentVersion:           a.version,
		Sections:               sections,
	})
	if err != nil {
		return err
	}
	if len(ack.StoredSections) > 0 {
		a.log.Printf("inventory stored for sections: %s", strings.Join(ack.StoredSections, ", "))
	}
	return nil
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
	// Proactively renew the bearer credential before it expires (issue #125).
	// This runs before the beat so the heartbeat uses the freshest token. A
	// definitive rejection (revoked/expired) is returned so the loop surfaces
	// the re-enrollment condition; transient failures are swallowed because the
	// current credential is still valid until its expiry.
	if err := a.maybeRenewCredential(ctx, s); err != nil {
		return err
	}
	if s.seen.Prune(time.Now().UTC()) {
		if err := s.seen.Save(); err != nil {
			return fatal(fmt.Errorf("persist pruned command journal: %w", err))
		}
	}
	sample := telemetry.CollectContext(ctx)
	// Collect once per process, then advertise digests every beat. Hardware
	// changes rarely and collection spawns PowerShell, so re-collecting on each
	// beat would cost far more than it could ever discover.
	if s.inventorySections == nil {
		s.inventorySections = inventory.Collect(ctx)
	}
	ack, err := s.api.HeartbeatWithPendingResults(
		ctx, sample, inventory.Hashes(s.inventorySections), pendingResultNotices(s.seen, 256),
	)
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
	// Upload only what the server asked for. A failure here is logged and
	// retried on the next beat rather than failing the check-in: inventory is
	// evidence, not control flow, and losing a beat over it would also delay
	// command delivery.
	if len(ack.InventoryRequested) > 0 {
		if err := a.submitInventory(ctx, s, ack.InventoryRequested); err != nil {
			a.log.Printf("failed to submit inventory: %v", err)
		}
	}
	var firstReportErr error
	if s.monitoringEval != nil {
		// Evaluate the revision-pinned effective policy returned by this
		// heartbeat. Results are persisted to a bounded outbox before upload, so
		// a lost response or process restart retries the same idempotency IDs.
		evaluated, err := s.monitoringEval.Evaluate(ctx, ack.MonitoringChecks, sample, time.Now().UTC())
		if err != nil {
			return fatal(fmt.Errorf("persist monitoring evaluation: %w", err))
		}
		if evaluated > 0 {
			a.log.Printf("evaluated %d monitoring check(s)", evaluated)
		}
		if err := a.flushMonitoringResults(ctx, s); err != nil {
			a.log.Printf("failed to flush monitoring results: %v", err)
			firstReportErr = err
		}
	}
	if err := a.flushPendingResults(ctx, s); err != nil {
		a.log.Printf("failed to flush pending command results: %v", err)
		firstReportErr = err
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
		return firstReportErr
	}
	// Concurrency contract: exactly one command runs at a time per agent
	// runtime. Commands in a heartbeat batch are executed strictly in the order
	// the server delivered them (which is FIFO by creation), and the next beat
	// is not issued until this batch drains, so there is no overlap between
	// batches either. The server's per-heartbeat batch cap bounds how many
	// arrive at once; this loop is what keeps them serialized.
	a.log.Printf("received %d command(s)", len(ack.PendingCommands))
	for i, cmd := range ack.PendingCommands {
		if err := a.processCommand(execCtx, s, cmd); err != nil {
			if isFatal(err) {
				return err
			}
			if firstReportErr == nil {
				firstReportErr = err
			}
		}
		// On shutdown, finish the current command but do not start new ones.
		if ctx.Err() != nil {
			if remaining := len(ack.PendingCommands) - i - 1; remaining > 0 {
				a.log.Printf("stop requested; deferring %d remaining command(s)", remaining)
			}
			break
		}
	}
	// A force-cancelled execution uses execCtx, which is already cancelled.
	// Give its durably stored result one bounded independent upload attempt
	// during shutdown; a failure remains in the outbox for the next start.
	reportCtx := ctx
	cancelReport := func() {}
	if ctx.Err() != nil {
		reportCtx, cancelReport = context.WithTimeout(context.Background(), 5*time.Second)
	}
	defer cancelReport()
	if err := a.flushPendingResults(reportCtx, s); err != nil {
		a.log.Printf("pending command results remain queued: %v", err)
		if firstReportErr == nil {
			firstReportErr = err
		}
	}
	return firstReportErr
}

// maybeRenewCredential rotates the agent bearer before it expires (issue #125).
// It renews at the midpoint between receipt and expiry, well ahead of the
// deadline, so an occasional failed attempt has many beats to recover before the
// credential lapses. Rotation is loss-safe: the server keeps the previous token
// valid for a bounded overlap, so a lost response or a failed local persist just
// means the agent keeps using the still-valid old token and retries with a fresh
// nonce next beat. The new token is adopted only after it is durably saved.
func (a *Agent) maybeRenewCredential(ctx context.Context, s *session) error {
	now := time.Now().UTC()
	if s.identity == nil || !credentialRenewDue(s.identity, now) {
		return nil
	}
	nonce, err := newRotationNonce()
	if err != nil {
		a.log.Printf("credential renewal skipped: %v", err)
		return nil
	}
	resp, err := s.api.RenewCredential(ctx, nonce)
	if err != nil {
		if client.IsUnauthorized(err) {
			// The credential was rejected outright: the agent is revoked or its
			// credential already expired past the overlap. Surface it so the loop
			// logs the revocation/re-enrollment condition instead of silently
			// spinning; the identity is kept on disk for operator investigation.
			a.log.Printf("credential renewal rejected by server; this agent may be revoked or its credential expired — re-enrollment is required")
			return err
		}
		a.log.Printf("credential renewal failed (%v); current credential still valid, will retry", err)
		return nil
	}

	// Persist before adopting. If the save fails, the server has already rotated
	// but the previous token stays valid through its overlap window, so we keep
	// the old token in memory and retry with a fresh nonce next beat rather than
	// switch to a token we could not durably record.
	prev := *s.identity
	s.identity.AgentToken = resp.AgentToken
	s.identity.CredentialExpiresAt = resp.CredentialExpiresAt
	s.identity.CredentialObtainedAt = now.Format(time.RFC3339Nano)
	if err := s.identity.Save(s.identityPath); err != nil {
		*s.identity = prev
		a.log.Printf("failed to persist renewed credential (%v); keeping current credential and retrying", err)
		return nil
	}
	s.api.SetToken(resp.AgentToken)
	a.log.Printf("renewed agent credential (generation %d)", resp.CredentialGeneration)
	return nil
}

// credentialRenewDue reports whether the credential should be renewed now. It is
// due once the clock passes the midpoint between when the credential was
// obtained and when it expires. A credential with no expiry (an older server
// that never issued one) is never due. Unparseable or missing receipt time falls
// back to "renew while still valid" so a one-time upgrade establishes the
// baseline; an already-expired credential is left for the heartbeat to surface.
func credentialRenewDue(id *config.Identity, now time.Time) bool {
	if id.CredentialExpiresAt == "" {
		return false
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, id.CredentialExpiresAt)
	if err != nil {
		return false
	}
	obtained, err := time.Parse(time.RFC3339Nano, id.CredentialObtainedAt)
	if err != nil || !obtained.Before(expiresAt) {
		return now.Before(expiresAt)
	}
	renewAt := obtained.Add(expiresAt.Sub(obtained) / 2)
	return !now.Before(renewAt)
}

// newRotationNonce returns a fresh high-entropy nonce for one renewal attempt.
// 24 random bytes encode to 32 URL-safe characters, within the server's
// 16..64 bound.
func newRotationNonce() (string, error) {
	var b [24]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate rotation nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (a *Agent) flushMonitoringResults(ctx context.Context, s *session) error {
	for {
		batch := s.monitoringStore.PendingBatch(100)
		if len(batch) == 0 {
			return nil
		}
		ack, err := s.api.SubmitMonitoringResults(ctx, batch)
		if err != nil {
			return err
		}
		acknowledged := ack.Accepted + ack.Duplicates
		if acknowledged != len(batch) {
			return fmt.Errorf("server acknowledged %d of %d monitoring results", acknowledged, len(batch))
		}
		if err := s.monitoringStore.AcknowledgePrefix(len(batch)); err != nil {
			return fatal(fmt.Errorf("persist monitoring acknowledgement: %w", err))
		}
	}
}

// processCommand runs the accept/refuse gate for one command in strict order:
// signature/shape -> signed time window -> nonce replay -> ID replay -> execute. A command that fails any gate is
// refused and never executed.
func (a *Agent) processCommand(ctx context.Context, s *session, cmd client.Command) error {
	if cmd.AgentID != s.agentID {
		a.log.Printf("REFUSING command %s: agent identity mismatch", cmd.ID)
		return a.queueResult(ctx, s, cmd.ID, time.Time{}, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: agent identity mismatch",
		})
	}

	var verifyErr error
	if cmd.EnvelopeVersion == protocol.CommandEnvelopeV3 {
		pub, ok := s.pubKeys[cmd.SigningKeyID]
		if !ok {
			a.log.Printf("REFUSING command %s: unknown or retired signing key %q", cmd.ID, cmd.SigningKeyID)
			return a.queueResult(ctx, s, cmd.ID, time.Time{}, client.CommandResult{ExitCode: -1, Stderr: "agent refused command: unknown signing key"})
		}
		verifyErr = verify.VerifyWithKeyID(pub, cmd.EnvelopeVersion, cmd.SchemaVersion, cmd.ID, s.agentID, cmd.Kind, cmd.Payload, cmd.IssuedAt, cmd.ExpiresAt, cmd.Nonce, cmd.SigningKeyID, cmd.Signature)
	} else {
		verifyErr = verify.Verify(s.pub, cmd.EnvelopeVersion, cmd.SchemaVersion, cmd.ID, s.agentID, cmd.Kind, cmd.Payload, cmd.IssuedAt, cmd.ExpiresAt, cmd.Nonce, cmd.Signature)
	}
	if err := verifyErr; err != nil {
		a.log.Printf("REFUSING command %s: signature invalid: %v", cmd.ID, err)
		return a.queueResult(ctx, s, cmd.ID, time.Time{}, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: signature verification failed",
		})
	}

	// Time window: all values are signed and required. Malformed, stale, overly
	// long-lived, or implausibly future commands fail closed.
	expiry, err := verify.ValidateCommandWindow(cmd.IssuedAt, cmd.ExpiresAt, time.Now().UTC())
	if err != nil {
		a.log.Printf("REFUSING command %s: invalid time window: %v", cmd.ID, err)
		return a.queueResult(ctx, s, cmd.ID, time.Time{}, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: invalid signed time window",
		})
	}

	// Replay: an id already accepted must never execute again. If the server
	// lost an acknowledged terminal row (for example after rollback), requeue
	// the exact retained result rather than clobbering it or rerunning work.
	if s.seen.Has(cmd.ID) {
		a.log.Printf("REFUSING command %s: already executed", cmd.ID)
		requeued, err := s.seen.RequeueAcknowledged(cmd.ID)
		if err != nil {
			return fatal(fmt.Errorf("requeue retained result for %s: %w", cmd.ID, err))
		}
		if requeued {
			a.log.Printf("server re-delivered acknowledged command %s; requeueing retained result without execution", cmd.ID)
		}
		return a.flushPendingResults(ctx, s)
	}

	if s.seen.HasNonce(cmd.Nonce) {
		a.log.Printf("REFUSING command %s: nonce already used", cmd.ID)
		return a.queueResult(ctx, s, cmd.ID, expiry, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: repeated nonce",
		})
	}

	// Reserve both replay keys durably before starting the process. If the agent
	// cannot persist this reservation, fail closed rather than execute a command
	// that could be replayed after a restart.
	if err := s.seen.ReserveCommand(cmd.ID, cmd.Nonce, expiry); err != nil {
		a.log.Printf("failed to persist replay store after %s: %v", cmd.ID, err)
		if queueErr := a.queueResult(ctx, s, cmd.ID, expiry, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: replay state could not be persisted",
		}); queueErr != nil {
			return fatal(fmt.Errorf("persist refusal result for %s: %w", cmd.ID, queueErr))
		}
		return nil
	}
	if err := s.seen.MarkExecuting(cmd.ID); err != nil {
		a.log.Printf("REFUSING command %s: executing transition could not be persisted: %v", cmd.ID, err)
		if queueErr := a.queueResult(ctx, s, cmd.ID, expiry, client.CommandResult{
			ExitCode: -1,
			Stderr:   "agent refused command: execution state could not be persisted",
		}); queueErr != nil {
			return fatal(fmt.Errorf("persist execution-state refusal for %s: %w", cmd.ID, queueErr))
		}
		return nil
	}

	a.log.Printf("executing command %s (kind=%s)", cmd.ID, cmd.Kind)
	var res executor.Result
	switch cmd.Kind {
	case executor.KindScanUpdates:
		res = a.runUpdateScan(ctx, s)
	case executor.KindInstallUpdates:
		res = a.runUpdateInstall(ctx, cmd.Payload)
	case executor.KindReboot, executor.KindShutdown, executor.KindCancelPowerAction:
		res = power.Execute(ctx, cmd.Kind, cmd.Payload)
	case executor.KindFileUpload, executor.KindFileDownload,
		executor.KindRegistryRead, executor.KindRegistryWrite,
		executor.KindRegistryDelete, executor.KindRemediationRollback:
		res = remediation.Execute(ctx, cmd.ID, cmd.Kind, cmd.Payload)
	case executor.KindQueryEventLog:
		res = eventlog.Execute(ctx, cmd.Kind, cmd.Payload)
	case executor.KindScanPackages:
		res = a.runPackageScan(ctx, s, cmd.Payload)
	case executor.KindInstallPackages:
		res = packages.ExecuteInstall(ctx, cmd.Kind, cmd.Payload, s.packagesConfig)
	case executor.KindDeploySoftware:
		res = deploy.Execute(ctx, cmd.Kind, cmd.Payload)
	default:
		script := extractScript(cmd.Payload)
		res = a.run(ctx, cmd.Kind, script)
	}

	result := client.CommandResult{
		ExitCode:         res.ExitCode,
		Stdout:           res.Stdout,
		Stderr:           res.Stderr,
		AgentCompletedAt: time.Now().UTC().Format(time.RFC3339Nano),
		StdoutTruncated:  res.StdoutTruncated,
		StderrTruncated:  res.StderrTruncated,
		StdoutTotalBytes: res.StdoutTotalBytes,
		StderrTotalBytes: res.StderrTotalBytes,
	}
	if err := s.seen.StoreResult(cmd.ID, expiry, result); err != nil {
		// The on-disk state remains "executing", so restart recovery will emit
		// an unknown-outcome failure without ever replaying the command.
		return fatal(fmt.Errorf("persist completed result for %s: %w", cmd.ID, err))
	}
	if err := a.flushPendingResults(ctx, s); err != nil {
		a.log.Printf("failed to report result for %s; retained for retry: %v", cmd.ID, err)
		return err
	}
	return nil
}

// runUpdateScan handles the scan_updates typed command (issue #51): it runs a
// bounded Windows Update scan, submits the normalized result through the ordinary
// inventory pipeline (so history/diff/views come for free), and returns a small
// JSON summary as the command output. The scan running here rather than on the
// heartbeat keeps the beat fast, and reuses the command path's one-at-a-time
// execution and 5-minute-plus bound.
func (a *Agent) runUpdateScan(ctx context.Context, s *session) executor.Result {
	section, summary, err := patching.Scan(ctx)
	if err != nil {
		return executor.Result{
			ExitCode: -1,
			Stderr:   "windows update scan failed: " + err.Error(),
		}
	}

	// Push the normalized section. A submission failure does not undo the scan;
	// it is surfaced on stderr so the operator knows the inventory view may lag.
	var stderr string
	if _, subErr := s.api.SubmitInventory(ctx, inventory.Submission{
		InventorySchemaVersion: inventory.SchemaVersion,
		AgentVersion:           a.version,
		Sections:               []inventory.Section{section},
	}); subErr != nil {
		a.log.Printf("scan_updates: inventory submission failed: %v", subErr)
		// Say what actually happened: nothing here retains or retries the
		// section, so this scan's data is gone and the inventory view will keep
		// showing the previous scan until a new one succeeds. The old wording
		// claimed the result was "retained on endpoint", which invited an
		// operator to wait for a retry that never comes.
		stderr = "inventory submission rejected; this scan's data was discarded and " +
			"the Windows Updates inventory still shows the previous scan — " +
			"re-run scan_updates once the cause is resolved: " + subErr.Error()
	}

	return updateScanCommandResult(summary, stderr)
}

// updateScanCommandResult keeps a Windows Update API failure from being
// presented as a successful command merely because a partial inventory payload
// could still be submitted.
func updateScanCommandResult(summary patching.Summary, stderr string) executor.Result {
	out, err := json.Marshal(summary)
	if err != nil {
		out = []byte(`{"status":"ok"}`)
	}
	exitCode := 0
	collectionError := summary.ErrorCode
	if collectionError == "" {
		collectionError = summary.HistoryErrorCode
	}
	if collectionError != "" {
		exitCode = 1
		if stderr != "" {
			stderr += "; "
		}
		stderr += "windows update collection reported " + collectionError
	}
	return executor.Result{ExitCode: exitCode, Stdout: string(out), Stderr: stderr}
}

// runPackageScan handles the scan_packages typed command (issue #55): it runs a
// bounded package-manager discovery, submits the normalized installed_packages
// section through the ordinary inventory pipeline (so history/diff/views come
// for free), and returns a small JSON summary as the command output. It mirrors
// runUpdateScan so a discovery failure surfaces on stderr without being reported
// as a successful command.
func (a *Agent) runPackageScan(ctx context.Context, s *session, rawPayload json.RawMessage) executor.Result {
	result, err := packages.Scan(ctx, rawPayload, s.packagesConfig)
	if err != nil {
		summary := packages.Summarize(result)
		summary.Message = "package scan failed: " + err.Error()
		out, _ := json.Marshal(summary)
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: summary.Message}
	}

	section := packages.BuildSection(result)
	var stderr string
	if _, subErr := s.api.SubmitInventory(ctx, inventory.Submission{
		InventorySchemaVersion: inventory.SchemaVersion,
		AgentVersion:           a.version,
		Sections:               []inventory.Section{section},
	}); subErr != nil {
		a.log.Printf("scan_packages: inventory submission failed: %v", subErr)
		stderr = "inventory submission rejected; this scan's data was discarded and " +
			"the installed_packages inventory still shows the previous scan — " +
			"re-run scan_packages once the cause is resolved: " + subErr.Error()
	}

	summary := packages.Summarize(result)
	out, err := json.Marshal(summary)
	if err != nil {
		out = []byte(`{"status":"ok"}`)
	}
	exitCode := 0
	if summary.ErrorCode != "" {
		exitCode = 1
	}
	return executor.Result{ExitCode: exitCode, Stdout: string(out), Stderr: stderr}
}

// Seams so install, active-user detection, and reboot scheduling can be faked in
// tests without shelling out to Windows Update or shutdown.exe (issue #53).
var (
	patchInstallWithRetry = patching.InstallWithRetry
	patchActiveUser       = power.ActiveUser
	patchScheduleReboot   = power.ScheduleReboot
)

// runUpdateInstall handles the install_updates typed command: it installs the
// selected updates (retrying failures up to the signed max_attempts) and applies
// the signed post-install reboot policy, if any.
func (a *Agent) runUpdateInstall(ctx context.Context, rawPayload json.RawMessage) executor.Result {
	var payload struct {
		InstallAll  bool     `json:"install_all"`
		KBIDs       []string `json:"kb_ids"`
		TargetKBs   []string `json:"target_kbs"`
		UpdateIDs   []string `json:"update_ids"`
		MaxAttempts int      `json:"max_attempts"`
		Reboot      *struct {
			Policy         string `json:"policy"`
			DelaySeconds   int    `json:"delay_seconds"`
			RequiresNoUser bool   `json:"requires_no_user"`
		} `json:"reboot"`
	}
	if len(rawPayload) > 0 {
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			return executor.Result{ExitCode: 1, Stderr: "windows update install payload is malformed"}
		}
	}
	targetKBs := append(append([]string{}, payload.KBIDs...), payload.TargetKBs...)
	maxAttempts := payload.MaxAttempts
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	installRes, err := patchInstallWithRetry(ctx, patching.InstallTargets{
		All:       payload.InstallAll,
		KBIDs:     targetKBs,
		UpdateIDs: payload.UpdateIDs,
	}, maxAttempts)
	if err != nil {
		outBytes, _ := json.Marshal(installRes)
		return executor.Result{
			ExitCode: -1,
			Stdout:   string(outBytes),
			Stderr:   "windows update install failed: " + err.Error(),
		}
	}

	// Post-install reboot policy (issue #53). Present only when the server
	// authorized a reboot for this capable agent. The result is durably stored by
	// processCommand after this returns; the signed delay (>=60s) leaves time to
	// upload before the OS restarts, mirroring the power-operation contract.
	if payload.Reboot != nil {
		user, _ := patchActiveUser(ctx)
		decision := patching.DecideReboot(patching.RebootDecisionInput{
			Policy:         payload.Reboot.Policy,
			RequiresNoUser: payload.Reboot.RequiresNoUser,
			RebootRequired: installRes.RebootRequired,
			ActiveUser:     user,
		})
		installRes.Reboot = &patching.RebootOutcome{
			Policy:       payload.Reboot.Policy,
			Decision:     decision,
			DelaySeconds: payload.Reboot.DelaySeconds,
		}
		if decision == patching.RebootScheduled {
			if _, _, rerr := patchScheduleReboot(ctx, payload.Reboot.DelaySeconds, "NodeLink post-install reboot"); rerr != nil {
				installRes.Reboot.Decision = "schedule_failed"
			}
		}
	}

	outBytes, _ := json.Marshal(installRes)
	exitCode := 0
	if installRes.Status == "failed" {
		exitCode = 1
	}
	return executor.Result{ExitCode: exitCode, Stdout: string(outBytes)}
}

func pendingResultNotices(store *SeenStore, limit int) []client.PendingResultNotice {
	pending := store.PendingResults()
	if len(pending) > limit {
		pending = pending[:limit]
	}
	notices := make([]client.PendingResultNotice, 0, len(pending))
	for _, item := range pending {
		notices = append(notices, client.PendingResultNotice{
			CommandID:        item.CommandID,
			AgentCompletedAt: item.Result.AgentCompletedAt,
		})
	}
	return notices
}

// queueResult persists before reporting, including refusal outcomes. A network
// failure is returned for backoff but never removes the durable outbox entry.
func (a *Agent) queueResult(
	ctx context.Context,
	s *session,
	commandID string,
	expiry time.Time,
	result client.CommandResult,
) error {
	if err := s.seen.StoreResult(commandID, expiry, result); err != nil {
		if errors.Is(err, errResultAlreadyStored) {
			return a.flushPendingResults(ctx, s)
		}
		return fatal(fmt.Errorf("persist result for %s: %w", commandID, err))
	}
	return a.flushPendingResults(ctx, s)
}

// flushPendingResults implements at-least-once delivery over the server's
// command-ID idempotency boundary. An acknowledgement is persisted only after
// HTTP success; a lost acknowledgement therefore causes an exact safe retry.
func (a *Agent) flushPendingResults(ctx context.Context, s *session) error {
	var firstErr error
	for _, pending := range s.seen.PendingResults() {
		if err := ctx.Err(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		if err := s.api.ReportResult(ctx, pending.CommandID, pending.Result); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := s.seen.Acknowledge(pending.CommandID); err != nil {
			return fatal(fmt.Errorf("persist result acknowledgement for %s: %w", pending.CommandID, err))
		}
	}
	return firstErr
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
