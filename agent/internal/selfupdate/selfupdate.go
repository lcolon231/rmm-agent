// SPDX-License-Identifier: AGPL-3.0-only
// Package selfupdate implements the signed, staged agent self-update and
// rollback contract of issue #63.
//
// The update instruction and its metadata ride the existing Ed25519-signed
// command envelope, so the version, channel, artifact URL, artifact digest, and
// anti-rollback floor are all covered by the server signature the agent already
// verifies before this package is entered. This package adds the endpoint half:
//
//  1. re-validate the signed metadata structurally and fail closed,
//  2. enforce the anti-rollback and channel rules against the running build,
//  3. download the artifact over HTTPS into a bounded staging file and verify
//     its SHA-256 (plus, on Windows, an optional pinned Authenticode signer),
//  4. record a durable journal, back up the running binary, and replace it
//     atomically,
//  5. restart the service and, on the next start, health-check the new build,
//  6. commit on success or automatically restore the retained previous build.
//
// Every step that can leave the endpoint in a partial state writes the journal
// first, so an interrupted download, a crash between stage and swap, a failed
// restart, or a new build that never becomes healthy all resolve to either the
// new build or the previous known-good build — never to no agent at all.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

const (
	// MaxArtifactBytes bounds a downloaded agent artifact so a hostile or
	// misconfigured source cannot exhaust the endpoint's disk.
	MaxArtifactBytes = 256 << 20 // 256 MiB
	// maxRedirects bounds the download redirect chain.
	maxRedirects = 5
	// downloadTimeout bounds the HTTPS transfer.
	downloadTimeout = 30 * time.Minute

	minHealthTimeoutSeconds = 60
	maxHealthTimeoutSeconds = 3600
	// defaultHealthTimeoutSeconds applies when the signed payload omits one.
	defaultHealthTimeoutSeconds = 600

	// maxHealthAttempts bounds how many starts may observe an installed-but-
	// unconfirmed build before the attempt is rolled back unconditionally. A
	// build that crashes before it can report healthy is the case this bounds.
	maxHealthAttempts = 3

	// updateDirName is the update root relative to the agent executable.
	updateDirName = ".nodelink-update"

	// ChannelStable and friends are the release channels an endpoint may follow.
	ChannelStable = "stable"
	ChannelBeta   = "beta"
	ChannelCanary = "canary"
)

// Result statuses. They are stable strings: the server stores them as attempt
// evidence and the canary halt rule counts them.
const (
	StatusInvalid           = "invalid"
	StatusAlreadyCurrent    = "already_current"
	StatusDowngradeRefused  = "downgrade_refused"
	StatusChannelMismatch   = "channel_mismatch"
	StatusPlatformMismatch  = "platform_mismatch"
	StatusUpdateInProgress  = "update_in_progress"
	StatusDownloadFailed    = "download_failed"
	StatusTampered          = "tampered"
	StatusSignatureMismatch = "signature_mismatch"
	StatusStageFailed       = "stage_failed"
	StatusInstallFailed     = "install_failed"
	StatusRestartPending    = "staged_restart_pending"
	StatusRestartFailed     = "restart_failed"
	StatusSucceeded         = "succeeded"
	StatusRolledBack        = "rolled_back"
	StatusFailed            = "failed"
	StatusUnsupported       = "unsupported"
	StatusNoPreviousBuild   = "no_previous_build"
)

var (
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	thumbprintPattern = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	idPattern         = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	platformPattern   = regexp.MustCompile(`^[a-z0-9]{1,16}/[a-z0-9]{1,16}$`)
	reasonPattern     = regexp.MustCompile(`^[\x20-\x7E]{1,256}$`)
)

// Function seams keep the network, platform calls, and the clock mockable.
var (
	downloadArtifact   = httpDownloadArtifact
	verifyAuthenticode = platformVerifyAuthenticode
	restartService     = platformRestartService
	nowUTC             = func() time.Time { return time.Now().UTC() }
)

// Options is the runtime context the caller (the service runner) owns. Tests
// and the runner both construct it explicitly rather than letting this package
// discover process state on its own.
type Options struct {
	// CurrentVersion is the version stamped into the running binary.
	CurrentVersion string
	// ExePath is the agent executable that will be replaced.
	ExePath string
	// Root is the update working directory (staging, backups, journal).
	Root string
	// Platform is the artifact selector this endpoint accepts, e.g.
	// "windows/amd64". A payload for any other platform fails closed.
	Platform string
	// Channel is the release channel this endpoint follows. Empty means the
	// endpoint accepts only the stable channel.
	Channel string
}

// DefaultRoot returns the update working directory next to an executable.
func DefaultRoot(exePath string) string {
	return filepath.Join(filepath.Dir(exePath), updateDirName)
}

func (o Options) normalized() (Options, error) {
	if o.ExePath == "" {
		return o, fmt.Errorf("agent executable path is unknown")
	}
	abs, err := filepath.Abs(o.ExePath)
	if err != nil {
		return o, fmt.Errorf("resolve agent executable path: %w", err)
	}
	o.ExePath = abs
	if o.Root == "" {
		o.Root = DefaultRoot(abs)
	}
	if o.Channel == "" {
		o.Channel = ChannelStable
	}
	if o.Platform == "" {
		return o, fmt.Errorf("endpoint platform is unknown")
	}
	if _, err := ParseVersion(o.CurrentVersion); err != nil {
		return o, fmt.Errorf("running build version is not comparable: %w", err)
	}
	return o, nil
}

type artifactSpec struct {
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type healthCheckSpec struct {
	TimeoutSeconds int `json:"timeout_seconds"`
}

type updatePayload struct {
	ReleaseID           string          `json:"release_id"`
	Version             string          `json:"version"`
	Channel             string          `json:"channel"`
	Platform            string          `json:"platform"`
	Artifact            artifactSpec    `json:"artifact"`
	MinSupportedVersion string          `json:"min_supported_version"`
	SignerThumbprint    string          `json:"signer_thumbprint,omitempty"`
	HealthCheck         healthCheckSpec `json:"health_check,omitempty"`
}

type rollbackPayload struct {
	Reason                 string `json:"reason"`
	Confirm                bool   `json:"confirm"`
	ExpectedCurrentVersion string `json:"expected_current_version,omitempty"`
}

// Result is the JSON evidence reported in the command's stdout. It carries only
// accountable metadata: versions, digests, outcome, and the reason code. The
// artifact URL never appears in the clear.
type Result struct {
	Status          string `json:"status"`
	ReleaseID       string `json:"release_id,omitempty"`
	FromVersion     string `json:"from_version,omitempty"`
	ToVersion       string `json:"to_version,omitempty"`
	ArtifactSHA256  string `json:"artifact_sha256,omitempty"`
	DownloadedBytes int64  `json:"downloaded_bytes,omitempty"`
	// RestartRequested records that the binary was replaced and the service
	// restart was requested; the outcome is decided after the restart.
	RestartRequested bool   `json:"restart_requested,omitempty"`
	HealthDeadline   string `json:"health_deadline,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Message          string `json:"message,omitempty"`
}

// Outcome is the post-restart resolution reported to the server so the staged
// rollout can count successes and failures and halt a bad release.
type Outcome struct {
	ReleaseID       string `json:"release_id,omitempty"`
	CommandID       string `json:"command_id,omitempty"`
	FromVersion     string `json:"from_version,omitempty"`
	ToVersion       string `json:"to_version,omitempty"`
	ObservedVersion string `json:"observed_version,omitempty"`
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	Attempts        int    `json:"attempts,omitempty"`
}

func decodeStrict(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func fail(res Result, status, reason, message string) executor.Result {
	res.Status = status
	res.Reason = reason
	res.Message = message
	out, _ := json.Marshal(res)
	return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: message}
}

func succeed(res Result) executor.Result {
	out, _ := json.Marshal(res)
	return executor.Result{ExitCode: 0, Stdout: string(out)}
}

// validate re-checks the signed payload structurally at the endpoint. The
// server validated it before signing; this is the fail-closed endpoint re-check
// that keeps a compromised or buggy server from widening the contract.
func validate(p updatePayload) error {
	if !idPattern.MatchString(p.ReleaseID) {
		return fmt.Errorf("release_id is invalid")
	}
	if _, err := ParseVersion(p.Version); err != nil {
		return fmt.Errorf("version is invalid: %w", err)
	}
	if _, err := ParseVersion(p.MinSupportedVersion); err != nil {
		return fmt.Errorf("min_supported_version is invalid: %w", err)
	}
	switch p.Channel {
	case ChannelStable, ChannelBeta, ChannelCanary:
	default:
		return fmt.Errorf("channel is invalid")
	}
	if !platformPattern.MatchString(p.Platform) {
		return fmt.Errorf("platform is invalid")
	}
	parsed, err := url.Parse(p.Artifact.URL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return fmt.Errorf("artifact url must be a valid https URL")
	}
	if !sha256Pattern.MatchString(p.Artifact.SHA256) {
		return fmt.Errorf("artifact sha256 must be a lowercase SHA-256 digest")
	}
	if p.Artifact.SizeBytes <= 0 || p.Artifact.SizeBytes > MaxArtifactBytes {
		return fmt.Errorf("artifact size_bytes must be between 1 and %d", MaxArtifactBytes)
	}
	if p.SignerThumbprint != "" && !thumbprintPattern.MatchString(p.SignerThumbprint) {
		return fmt.Errorf("signer_thumbprint must be a 40-char hex thumbprint")
	}
	if p.HealthCheck.TimeoutSeconds != 0 &&
		(p.HealthCheck.TimeoutSeconds < minHealthTimeoutSeconds ||
			p.HealthCheck.TimeoutSeconds > maxHealthTimeoutSeconds) {
		return fmt.Errorf("health_check.timeout_seconds must be between %d and %d",
			minHealthTimeoutSeconds, maxHealthTimeoutSeconds)
	}
	return nil
}

// Execute runs one agent_self_update or agent_update_rollback command.
func Execute(ctx context.Context, commandID, kind string, raw json.RawMessage, opts Options) executor.Result {
	normalized, err := opts.normalized()
	if err != nil {
		return fail(Result{}, StatusInvalid, "endpoint_state_unusable", "self-update is unavailable: "+err.Error())
	}
	switch kind {
	case executor.KindAgentSelfUpdate:
		return executeUpdate(ctx, commandID, raw, normalized)
	case executor.KindAgentUpdateRollback:
		return executeRollback(ctx, commandID, raw, normalized)
	default:
		return fail(Result{}, StatusUnsupported, "unsupported_kind", "unsupported self-update operation")
	}
}

func executeUpdate(ctx context.Context, commandID string, raw json.RawMessage, opts Options) executor.Result {
	var p updatePayload
	if err := decodeStrict(raw, &p); err != nil {
		return fail(Result{}, StatusInvalid, "payload_malformed", "agent_self_update payload is invalid")
	}
	if err := validate(p); err != nil {
		return fail(Result{ReleaseID: p.ReleaseID}, StatusInvalid, "payload_invalid",
			"agent_self_update payload is invalid: "+err.Error())
	}

	res := Result{
		ReleaseID:      p.ReleaseID,
		FromVersion:    opts.CurrentVersion,
		ToVersion:      p.Version,
		ArtifactSHA256: p.Artifact.SHA256,
	}

	// The endpoint only accepts artifacts built for it and releases on the
	// channel it follows. Both are signed, so a mismatch is a server or operator
	// error, not something to reconcile locally.
	if p.Platform != opts.Platform {
		return fail(res, StatusPlatformMismatch, "platform_mismatch",
			"release artifact targets a different platform than this endpoint")
	}
	if p.Channel != opts.Channel {
		return fail(res, StatusChannelMismatch, "channel_mismatch",
			"release channel does not match the channel this endpoint follows")
	}

	// Anti-rollback. The update path only ever moves forward: an equal version
	// is a no-op and a lower one is refused outright, so a replayed or
	// downgrade-shaped release can never reintroduce a withdrawn build. The
	// signed floor additionally refuses a target the publisher has retired.
	current, _ := ParseVersion(opts.CurrentVersion)
	target, _ := ParseVersion(p.Version)
	floor, _ := ParseVersion(p.MinSupportedVersion)
	switch {
	case Compare(target, current) == 0:
		res.Status = StatusAlreadyCurrent
		res.Reason = "already_current"
		return succeed(res)
	case Compare(target, current) < 0:
		return fail(res, StatusDowngradeRefused, "downgrade_refused",
			"refusing to install an older build than the running one")
	case Compare(target, floor) < 0:
		return fail(res, StatusDowngradeRefused, "below_min_supported_version",
			"refusing a target below the release's minimum supported version")
	}

	// One attempt at a time. A second update dispatched while a swap is pending
	// would race the restart and could strand the endpoint between builds.
	existing, err := loadJournal(opts.Root)
	if err != nil {
		return fail(res, StatusInvalid, "journal_unreadable",
			"existing update journal could not be read: "+err.Error())
	}
	if existing != nil && (existing.State == StateStaged || existing.State == StateInstalled) {
		return fail(res, StatusUpdateInProgress, "update_in_progress",
			"another self-update attempt is already in flight")
	}

	stagingDir := filepath.Join(opts.Root, "staging")
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return fail(res, StatusStageFailed, "staging_unavailable",
			"update staging directory could not be created: "+err.Error())
	}

	// 1. Download into staging, streaming the digest as we go.
	stagedPath, size, digest, err := downloadArtifact(ctx, p.Artifact.URL, stagingDir, p.Artifact.SizeBytes)
	if err != nil {
		if stagedPath != "" {
			os.Remove(stagedPath)
		}
		// An interrupted or truncated transfer lands here and leaves nothing
		// installed: the running build keeps serving.
		return fail(res, StatusDownloadFailed, "download_failed",
			"agent artifact download failed: "+err.Error())
	}
	res.DownloadedBytes = size

	// 2. Integrity. The digest is mandatory and covered by the command
	// signature, so a mismatch means the artifact was tampered with in transit
	// or at rest at the source.
	if digest != p.Artifact.SHA256 {
		os.Remove(stagedPath)
		return fail(res, StatusTampered, "artifact_digest_mismatch",
			fmt.Sprintf("artifact digest mismatch: expected %s, got %s", p.Artifact.SHA256, digest))
	}
	if size != p.Artifact.SizeBytes {
		os.Remove(stagedPath)
		return fail(res, StatusTampered, "artifact_size_mismatch",
			"artifact size did not match the signed metadata")
	}

	// 3. Optional pinned Authenticode signer, on top of the digest.
	if p.SignerThumbprint != "" {
		ok, thumb, sigErr := verifyAuthenticode(ctx, stagedPath)
		if sigErr != nil || !ok || !strings.EqualFold(thumb, p.SignerThumbprint) {
			os.Remove(stagedPath)
			return fail(res, StatusSignatureMismatch, "authenticode_mismatch",
				"agent artifact signer did not match the pinned Authenticode thumbprint")
		}
	}

	// 4. Journal the staged attempt before touching the installed binary.
	deadline := nowUTC().Add(healthTimeout(p))
	journal := &Journal{
		State:          StateStaged,
		ReleaseID:      p.ReleaseID,
		CommandID:      commandID,
		FromVersion:    opts.CurrentVersion,
		ToVersion:      p.Version,
		ExePath:        opts.ExePath,
		BackupPath:     backupPath(opts, opts.CurrentVersion),
		StagedPath:     stagedPath,
		ArtifactSHA256: p.Artifact.SHA256,
		StartedAt:      nowUTC().Format(time.RFC3339Nano),
		HealthDeadline: deadline.Format(time.RFC3339Nano),
	}
	if err := saveJournal(opts.Root, journal); err != nil {
		os.Remove(stagedPath)
		return fail(res, StatusStageFailed, "journal_write_failed",
			"update journal could not be persisted: "+err.Error())
	}

	// 5. Back up the running binary, then replace it atomically. The backup is
	// what the automatic rollback restores, so it is digested and journalled
	// before the swap.
	backupDigest, err := backupCurrent(opts, journal.BackupPath)
	if err != nil {
		os.Remove(stagedPath)
		journal.State = StateFailed
		journal.Reason = "backup_failed"
		_ = saveJournal(opts.Root, journal)
		return fail(res, StatusInstallFailed, "backup_failed",
			"running agent binary could not be backed up: "+err.Error())
	}
	journal.BackupSHA256 = backupDigest
	if err := saveJournal(opts.Root, journal); err != nil {
		os.Remove(stagedPath)
		return fail(res, StatusInstallFailed, "journal_write_failed",
			"update journal could not be persisted: "+err.Error())
	}

	if err := atomicReplace(stagedPath, opts.ExePath); err != nil {
		// Nothing was replaced, or the replace was undone; restore defensively
		// so a partial swap can never leave the endpoint without a binary.
		_ = restoreBackup(journal.BackupPath, opts.ExePath, journal.BackupSHA256)
		os.Remove(stagedPath)
		journal.State = StateFailed
		journal.Reason = "replace_failed"
		_ = saveJournal(opts.Root, journal)
		return fail(res, StatusInstallFailed, "replace_failed",
			"agent binary could not be replaced atomically: "+err.Error())
	}
	journal.State = StateInstalled
	journal.StagedPath = ""
	if err := saveJournal(opts.Root, journal); err != nil {
		// The new binary is in place but the journal is not durable, so a
		// restart could not health-check or roll back. Restore immediately.
		_ = restoreBackup(journal.BackupPath, opts.ExePath, journal.BackupSHA256)
		return fail(res, StatusInstallFailed, "journal_write_failed",
			"update journal could not be persisted after install; previous build restored")
	}

	// 6. Ask the service manager to restart into the new build. The outcome is
	// decided by the health check on the next start, not here.
	res.RestartRequested = true
	res.HealthDeadline = journal.HealthDeadline
	if err := restartService(ctx); err != nil {
		// The restart could not even be requested. Roll back now rather than
		// leaving a replaced-but-never-started build behind.
		reason := "restart_request_failed"
		if restoreErr := restoreBackup(journal.BackupPath, opts.ExePath, journal.BackupSHA256); restoreErr != nil {
			journal.State = StateFailed
			journal.Reason = "restart_and_restore_failed"
			_ = saveJournal(opts.Root, journal)
			return fail(res, StatusInstallFailed, "restart_and_restore_failed",
				"service restart could not be requested and the previous build could not be restored")
		}
		journal.State = StateRolledBack
		journal.Reason = reason
		_ = saveJournal(opts.Root, journal)
		res.RestartRequested = false
		return fail(res, StatusRestartFailed, reason,
			"service restart could not be requested; previous build restored")
	}

	res.Status = StatusRestartPending
	res.Reason = "awaiting_health_check"
	return succeed(res)
}

func healthTimeout(p updatePayload) time.Duration {
	seconds := p.HealthCheck.TimeoutSeconds
	if seconds == 0 {
		seconds = defaultHealthTimeoutSeconds
	}
	return time.Duration(seconds) * time.Second
}

func executeRollback(ctx context.Context, commandID string, raw json.RawMessage, opts Options) executor.Result {
	var p rollbackPayload
	if err := decodeStrict(raw, &p); err != nil {
		return fail(Result{}, StatusInvalid, "payload_malformed", "agent_update_rollback payload is invalid")
	}
	if !p.Confirm || !reasonPattern.MatchString(p.Reason) {
		return fail(Result{}, StatusInvalid, "payload_invalid",
			"agent_update_rollback requires confirm=true and a printable reason")
	}
	if p.ExpectedCurrentVersion != "" && p.ExpectedCurrentVersion != opts.CurrentVersion {
		return fail(Result{FromVersion: opts.CurrentVersion}, StatusInvalid, "version_precondition_failed",
			"running build does not match the expected version for this rollback")
	}

	previous, err := loadPrevious(opts.Root)
	if err != nil {
		return fail(Result{FromVersion: opts.CurrentVersion}, StatusFailed, "previous_build_unreadable",
			"retained previous build record could not be read: "+err.Error())
	}
	res := Result{FromVersion: opts.CurrentVersion}
	if previous == nil {
		return fail(res, StatusNoPreviousBuild, "no_previous_build",
			"no retained previous build is available to roll back to")
	}
	res.ToVersion = previous.Version
	res.ArtifactSHA256 = previous.SHA256

	if err := restoreBackup(previous.Path, opts.ExePath, previous.SHA256); err != nil {
		return fail(res, StatusFailed, "restore_failed",
			"retained previous build could not be restored: "+err.Error())
	}
	journal := &Journal{
		State:          StateRolledBack,
		CommandID:      commandID,
		FromVersion:    opts.CurrentVersion,
		ToVersion:      previous.Version,
		ExePath:        opts.ExePath,
		BackupPath:     previous.Path,
		BackupSHA256:   previous.SHA256,
		ArtifactSHA256: previous.SHA256,
		StartedAt:      nowUTC().Format(time.RFC3339Nano),
		HealthDeadline: nowUTC().Add(defaultHealthTimeoutSeconds * time.Second).Format(time.RFC3339Nano),
		Reason:         "operator_requested_rollback",
	}
	if err := saveJournal(opts.Root, journal); err != nil {
		return fail(res, StatusFailed, "journal_write_failed",
			"rollback journal could not be persisted: "+err.Error())
	}
	res.RestartRequested = true
	if err := restartService(ctx); err != nil {
		return fail(res, StatusRestartFailed, "restart_request_failed",
			"previous build was restored but the service restart could not be requested")
	}
	res.Status = StatusRolledBack
	res.Reason = "operator_requested_rollback"
	return succeed(res)
}

// Resolve is called once early in agent startup. It decides the fate of an
// in-flight attempt: commit the new build when it is healthy, or restore the
// retained previous build when it is not. It returns the outcome to report to
// the server, or nil when no attempt is in flight.
//
// healthy is supplied by the caller and must return nil only when the running
// build has demonstrably reached a working state (for NodeLink: a successful
// authenticated server check-in).
func Resolve(ctx context.Context, opts Options, healthy func(context.Context) error) (*Outcome, error) {
	normalized, err := opts.normalized()
	if err != nil {
		return nil, err
	}
	opts = normalized

	journal, err := loadJournal(opts.Root)
	if err != nil {
		// Unusable recovery state must not silently disable rollback. Surface it
		// and clear the journal so the endpoint keeps running the build on disk.
		_ = clearJournal(opts.Root)
		return nil, fmt.Errorf("update journal is unusable: %w", err)
	}
	if journal == nil {
		return nil, nil
	}

	switch journal.State {
	case StateStaged:
		// The process died between staging and the swap. Nothing was replaced.
		if journal.StagedPath != "" {
			os.Remove(journal.StagedPath)
		}
		journal.State = StateFailed
		journal.Reason = "interrupted_before_install"
		if err := saveJournal(opts.Root, journal); err != nil {
			return nil, err
		}
		return outcomeOf(journal, opts, StatusFailed), nil

	case StateInstalled:
		return resolveInstalled(ctx, opts, journal, healthy)

	case StateCommitted:
		return outcomeOf(journal, opts, StatusSucceeded), nil
	case StateRolledBack:
		return outcomeOf(journal, opts, StatusRolledBack), nil
	case StateFailed:
		return outcomeOf(journal, opts, StatusFailed), nil
	default:
		journal.State = StateFailed
		journal.Reason = "unknown_journal_state"
		_ = saveJournal(opts.Root, journal)
		return outcomeOf(journal, opts, StatusFailed), nil
	}
}

func resolveInstalled(
	ctx context.Context,
	opts Options,
	journal *Journal,
	healthy func(context.Context) error,
) (*Outcome, error) {
	// Count this start before the check runs, so a build that crashes during
	// the health check still exhausts its attempts instead of looping.
	journal.Attempts++
	if err := saveJournal(opts.Root, journal); err != nil {
		return nil, err
	}

	if journal.ExePath != opts.ExePath {
		return rollback(ctx, opts, journal, "installation_path_changed")
	}
	if opts.CurrentVersion != journal.ToVersion {
		// The restart did not actually bring up the new build (a stale service
		// image, a failed swap, or an unexpected binary). Restore explicitly.
		return rollback(ctx, opts, journal, "version_mismatch_after_restart")
	}
	if journal.Attempts > maxHealthAttempts {
		return rollback(ctx, opts, journal, "health_check_attempts_exhausted")
	}
	if deadline, ok := parseJournalTime(journal.HealthDeadline); ok && nowUTC().After(deadline) {
		return rollback(ctx, opts, journal, "health_check_deadline_exceeded")
	}
	if healthy == nil {
		return rollback(ctx, opts, journal, "health_check_unavailable")
	}
	if err := healthy(ctx); err != nil {
		return rollback(ctx, opts, journal, "health_check_failed")
	}

	// Healthy: keep the backup as the retained previous build so an operator can
	// still roll back deliberately later.
	if err := savePrevious(opts.Root, &previousBuild{
		Version: journal.FromVersion,
		Path:    journal.BackupPath,
		SHA256:  journal.BackupSHA256,
	}); err != nil {
		return nil, err
	}
	journal.State = StateCommitted
	journal.Reason = "health_check_passed"
	if err := saveJournal(opts.Root, journal); err != nil {
		return nil, err
	}
	_ = os.RemoveAll(filepath.Join(opts.Root, "staging"))
	// The displaced previous image stays locked while the old process exits;
	// clearing it here, on the first healthy start, is the earliest safe point.
	pruneDisplacedImages(opts.ExePath)
	return outcomeOf(journal, opts, StatusSucceeded), nil
}

func rollback(ctx context.Context, opts Options, journal *Journal, reason string) (*Outcome, error) {
	journal.Reason = reason
	if err := restoreBackup(journal.BackupPath, opts.ExePath, journal.BackupSHA256); err != nil {
		// Nothing safe is left to do automatically: report loudly and leave the
		// journal terminal so the endpoint does not loop.
		journal.State = StateFailed
		journal.Reason = reason + "+restore_failed"
		_ = saveJournal(opts.Root, journal)
		return outcomeOf(journal, opts, StatusFailed), nil
	}
	journal.State = StateRolledBack
	if err := saveJournal(opts.Root, journal); err != nil {
		return nil, err
	}
	// Restart into the restored build. A failed restart request is not fatal:
	// the service manager or the next start still runs the restored binary.
	_ = restartService(ctx)
	return outcomeOf(journal, opts, StatusRolledBack), nil
}

func outcomeOf(journal *Journal, opts Options, status string) *Outcome {
	return &Outcome{
		ReleaseID:       journal.ReleaseID,
		CommandID:       journal.CommandID,
		FromVersion:     journal.FromVersion,
		ToVersion:       journal.ToVersion,
		ObservedVersion: opts.CurrentVersion,
		Status:          status,
		Reason:          journal.Reason,
		Attempts:        journal.Attempts,
	}
}

// Acknowledge clears a resolved attempt after the server has accepted its
// outcome. A terminal journal is kept until then so a reporting failure never
// loses the evidence a halted rollout depends on.
func Acknowledge(opts Options) error {
	normalized, err := opts.normalized()
	if err != nil {
		return err
	}
	journal, err := loadJournal(normalized.Root)
	if err != nil || journal == nil {
		return clearJournal(normalized.Root)
	}
	switch journal.State {
	case StateStaged, StateInstalled:
		return nil // still in flight; nothing to acknowledge
	default:
		return clearJournal(normalized.Root)
	}
}

// previousBuild is the retained known-good build an operator-triggered rollback
// restores after an update has already been committed.
type previousBuild struct {
	Version string `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

func previousPath(root string) string { return filepath.Join(root, "previous.json") }

func loadPrevious(root string) (*previousBuild, error) {
	raw, err := os.ReadFile(previousPath(root))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var value previousBuild
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	if value.Path == "" || !sha256Pattern.MatchString(value.SHA256) {
		return nil, fmt.Errorf("retained previous build record is incomplete")
	}
	return &value, nil
}

func savePrevious(root string, value *previousBuild) error {
	if value.Path == "" || value.SHA256 == "" {
		return nil
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}
	return os.WriteFile(previousPath(root), encoded, 0o600)
}

func backupPath(opts Options, version string) string {
	safe := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '.' || r == '-' {
			return r
		}
		return '_'
	}, version)
	return filepath.Join(opts.Root, "backup", "rmm-agent-"+safe+".bak")
}

// backupCurrent copies the running binary aside and returns its digest.
func backupCurrent(opts Options, dest string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", err
	}
	digest, err := copyFile(opts.ExePath, dest)
	if err != nil {
		return "", err
	}
	return digest, nil
}

// restoreBackup puts a retained build back in place, refusing to install one
// whose digest no longer matches what was recorded when it was retained.
func restoreBackup(backup, exePath, expectedDigest string) error {
	if backup == "" {
		return fmt.Errorf("no backup path recorded")
	}
	actual, err := fileDigest(backup)
	if err != nil {
		return fmt.Errorf("retained build is unreadable: %w", err)
	}
	if expectedDigest != "" && actual != expectedDigest {
		return fmt.Errorf("retained build digest mismatch; refusing to restore")
	}
	restoreTmp := exePath + ".restore.tmp"
	if _, err := copyFile(backup, restoreTmp); err != nil {
		os.Remove(restoreTmp)
		return err
	}
	if err := atomicReplace(restoreTmp, exePath); err != nil {
		os.Remove(restoreTmp)
		return err
	}
	return nil
}

// atomicReplace moves src onto dest. Both paths live on the same volume (the
// staging directory sits next to the executable), so the rename is atomic and
// no window exists in which dest does not exist. On Windows the running image
// is displaced first, because an executing binary cannot be overwritten in
// place but can be renamed.
func atomicReplace(src, dest string) error {
	if err := os.Chmod(src, 0o755); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := replaceRunningBinary(src, dest); err != nil {
		return err
	}
	return nil
}

func copyFile(src, dest string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o700)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(out, hasher), in); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return "", err
	}
	if err := out.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// httpDownloadArtifact streams an HTTPS URL into the staging directory,
// enforcing the signed size bound and refusing any redirect that leaves HTTPS.
// It returns the staged path, the byte count, and the lowercase SHA-256 digest.
// A truncated or interrupted transfer returns an error with the partial file
// still named, so the caller can remove it; nothing is ever installed from it.
func httpDownloadArtifact(ctx context.Context, rawURL, stagingDir string, maxBytes int64) (string, int64, string, error) {
	if maxBytes <= 0 || maxBytes > MaxArtifactBytes {
		maxBytes = MaxArtifactBytes
	}
	client := &http.Client{
		Timeout: downloadTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("too many redirects")
			}
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("refusing redirect to non-https URL")
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, "", fmt.Errorf("source returned HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(stagingDir, "nodelink-agent-*.staged")
	if err != nil {
		return "", 0, "", err
	}
	path := tmp.Name()
	hasher := sha256.New()
	// Read one extra byte so an over-size body is detected rather than silently cut.
	written, copyErr := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(resp.Body, maxBytes+1))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	switch {
	case copyErr != nil:
		return path, 0, "", fmt.Errorf("transfer interrupted: %w", copyErr)
	case syncErr != nil:
		return path, 0, "", syncErr
	case closeErr != nil:
		return path, 0, "", closeErr
	case written > maxBytes:
		return path, 0, "", fmt.Errorf("artifact exceeds the signed %d-byte size", maxBytes)
	}
	return path, written, hex.EncodeToString(hasher.Sum(nil)), nil
}
