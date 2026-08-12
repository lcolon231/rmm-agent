// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

const (
	oldBinary = "OLD-AGENT-BINARY"
	newBinary = "NEW-AGENT-BINARY"
)

func digestOf(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// harness builds a temporary installation: an executable file plus an update
// root, with the network and the service manager replaced by stubs.
type harness struct {
	t        *testing.T
	opts     Options
	restarts int
	// restartErr, when set, makes the restart request fail.
	restartErr error
}

func newHarness(t *testing.T, currentVersion string) *harness {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "rmm-agent")
	if err := os.WriteFile(exe, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{
		t: t,
		opts: Options{
			CurrentVersion: currentVersion,
			ExePath:        exe,
			Root:           filepath.Join(dir, "update"),
			Platform:       "windows/amd64",
			Channel:        ChannelStable,
		},
	}

	origDownload, origRestart, origAuth, origNow := downloadArtifact, restartService, verifyAuthenticode, nowUTC
	restartService = func(context.Context) error {
		h.restarts++
		return h.restartErr
	}
	t.Cleanup(func() {
		downloadArtifact, restartService, verifyAuthenticode, nowUTC = origDownload, origRestart, origAuth, origNow
	})
	return h
}

// serveArtifact makes the real HTTPS download path deliver content.
func (h *harness) serveArtifact(content string) {
	h.t.Helper()
	downloadArtifact = func(ctx context.Context, _ string, stagingDir string, maxBytes int64) (string, int64, string, error) {
		file, err := os.CreateTemp(stagingDir, "staged-*")
		if err != nil {
			return "", 0, "", err
		}
		defer file.Close()
		if _, err := file.WriteString(content); err != nil {
			return file.Name(), 0, "", err
		}
		return file.Name(), int64(len(content)), digestOf(content), nil
	}
}

func (h *harness) exeContent() string {
	h.t.Helper()
	raw, err := os.ReadFile(h.opts.ExePath)
	if err != nil {
		h.t.Fatalf("read installed binary: %v", err)
	}
	return string(raw)
}

func (h *harness) journal() *Journal {
	h.t.Helper()
	journal, err := loadJournal(h.opts.Root)
	if err != nil {
		h.t.Fatalf("load journal: %v", err)
	}
	return journal
}

func updatePayloadJSON(overrides map[string]any) json.RawMessage {
	payload := map[string]any{
		"release_id":            "rel-0002",
		"version":               "0.2.0",
		"channel":               "stable",
		"platform":              "windows/amd64",
		"min_supported_version": "0.1.0",
		"artifact": map[string]any{
			"url":        "https://releases.example/rmm-agent-0.2.0.exe",
			"sha256":     digestOf(newBinary),
			"size_bytes": len(newBinary),
		},
		"health_check": map[string]any{"timeout_seconds": 300},
	}
	for key, value := range overrides {
		if value == nil {
			delete(payload, key)
			continue
		}
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func decodeResult(t *testing.T, res executor.Result) Result {
	t.Helper()
	var value Result
	if err := json.Unmarshal([]byte(res.Stdout), &value); err != nil {
		t.Fatalf("decode result evidence %q: %v", res.Stdout, err)
	}
	return value
}

func runUpdate(t *testing.T, h *harness, payload json.RawMessage) Result {
	t.Helper()
	return decodeResult(t, Execute(context.Background(), "cmd-1", executor.KindAgentSelfUpdate, payload, h.opts))
}

// --------------------------------------------------------------------------
// Version ordering and anti-rollback arithmetic
// --------------------------------------------------------------------------

func TestParseVersionRejectsUncomparableValues(t *testing.T) {
	for _, raw := range []string{"", "1.2", "v1.2.3", "1.2.3.4", "1.2.3+build7", "latest", "0.1.0-dev "} {
		if _, err := ParseVersion(raw); err == nil {
			t.Errorf("ParseVersion(%q) should fail closed", raw)
		}
	}
}

func TestCompareOrdersReleasesAndPrereleases(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.1.0", "0.2.0", -1},
		{"0.2.0", "0.1.9", 1},
		{"1.0.0", "1.0.0", 0},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-rc.1", "1.0.0-rc.2", -1},
		{"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"0.10.0", "0.9.0", 1},
	}
	for _, tc := range cases {
		a, err := ParseVersion(tc.a)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.a, err)
		}
		b, err := ParseVersion(tc.b)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.b, err)
		}
		if got := Compare(a, b); got != tc.want {
			t.Errorf("Compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// --------------------------------------------------------------------------
// Payload validation: the fail-closed endpoint re-check
// --------------------------------------------------------------------------

func TestUpdateRejectsInvalidPayloads(t *testing.T) {
	cases := map[string]map[string]any{
		"plaintext artifact url": {"artifact": map[string]any{
			"url": "http://releases.example/a.exe", "sha256": digestOf(newBinary), "size_bytes": len(newBinary),
		}},
		"uppercase digest": {"artifact": map[string]any{
			"url": "https://releases.example/a.exe", "sha256": strings.ToUpper(digestOf(newBinary)), "size_bytes": len(newBinary),
		}},
		"zero size": {"artifact": map[string]any{
			"url": "https://releases.example/a.exe", "sha256": digestOf(newBinary), "size_bytes": 0,
		}},
		"oversize artifact": {"artifact": map[string]any{
			"url": "https://releases.example/a.exe", "sha256": digestOf(newBinary), "size_bytes": MaxArtifactBytes + 1,
		}},
		"unknown channel":         {"channel": "nightly"},
		"malformed platform":      {"platform": "Windows/AMD64"},
		"uncomparable version":    {"version": "latest"},
		"uncomparable floor":      {"min_supported_version": "none"},
		"short signer thumbprint": {"signer_thumbprint": "ABC123"},
		"health timeout too low":  {"health_check": map[string]any{"timeout_seconds": 5}},
		"health timeout too high": {"health_check": map[string]any{"timeout_seconds": 100000}},
		"missing release id":      {"release_id": ""},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "0.1.0")
			h.serveArtifact(newBinary)
			res := runUpdate(t, h, updatePayloadJSON(overrides))
			if res.Status != StatusInvalid {
				t.Fatalf("status = %q, want %q", res.Status, StatusInvalid)
			}
			if h.exeContent() != oldBinary {
				t.Fatal("an invalid payload must not touch the installed binary")
			}
		})
	}
}

func TestUpdateRejectsUnknownPayloadFields(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	raw := []byte(`{"release_id":"rel-1","version":"0.2.0","channel":"stable","platform":"windows/amd64",
	  "min_supported_version":"0.1.0","artifact":{"url":"https://x.example/a","sha256":"` + digestOf(newBinary) + `","size_bytes":16},
	  "run_script":"whoami"}`)
	res := runUpdate(t, h, raw)
	if res.Status != StatusInvalid || res.Reason != "payload_malformed" {
		t.Fatalf("unknown field must be refused, got status=%q reason=%q", res.Status, res.Reason)
	}
}

// --------------------------------------------------------------------------
// Anti-rollback, channel, and platform policy
// --------------------------------------------------------------------------

func TestUpdateRefusesDowngrade(t *testing.T) {
	h := newHarness(t, "0.3.0")
	h.serveArtifact(newBinary)
	res := runUpdate(t, h, updatePayloadJSON(nil))
	if res.Status != StatusDowngradeRefused || res.Reason != "downgrade_refused" {
		t.Fatalf("status=%q reason=%q, want downgrade refusal", res.Status, res.Reason)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("a refused downgrade must leave the running build installed")
	}
	if h.journal() != nil {
		t.Fatal("a refused downgrade must not open an update attempt")
	}
}

func TestUpdateRefusesTargetBelowMinSupportedVersion(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	res := runUpdate(t, h, updatePayloadJSON(map[string]any{"min_supported_version": "0.5.0"}))
	if res.Status != StatusDowngradeRefused || res.Reason != "below_min_supported_version" {
		t.Fatalf("status=%q reason=%q, want anti-rollback floor refusal", res.Status, res.Reason)
	}
}

func TestUpdateToSameVersionIsANoOp(t *testing.T) {
	h := newHarness(t, "0.2.0")
	h.serveArtifact(newBinary)
	res := runUpdate(t, h, updatePayloadJSON(nil))
	if res.Status != StatusAlreadyCurrent {
		t.Fatalf("status = %q, want %q", res.Status, StatusAlreadyCurrent)
	}
	if h.restarts != 0 {
		t.Fatal("a no-op update must not restart the service")
	}
}

func TestUpdateRefusesForeignChannelAndPlatform(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)

	res := runUpdate(t, h, updatePayloadJSON(map[string]any{"channel": "canary"}))
	if res.Status != StatusChannelMismatch {
		t.Fatalf("channel status = %q, want %q", res.Status, StatusChannelMismatch)
	}

	res = runUpdate(t, h, updatePayloadJSON(map[string]any{"platform": "linux/arm64"}))
	if res.Status != StatusPlatformMismatch {
		t.Fatalf("platform status = %q, want %q", res.Status, StatusPlatformMismatch)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("a mismatched release must not be installed")
	}
}

// --------------------------------------------------------------------------
// Artifact integrity
// --------------------------------------------------------------------------

func TestUpdateRefusesTamperedArtifact(t *testing.T) {
	h := newHarness(t, "0.1.0")
	// The source serves different bytes than the signed metadata pins.
	h.serveArtifact("TAMPERED-AGENT-BINARY")
	res := runUpdate(t, h, updatePayloadJSON(nil))
	if res.Status != StatusTampered || res.Reason != "artifact_digest_mismatch" {
		t.Fatalf("status=%q reason=%q, want a tamper refusal", res.Status, res.Reason)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("a tampered artifact must never be installed")
	}
	if h.restarts != 0 {
		t.Fatal("a tampered artifact must not restart the service")
	}
	entries, _ := os.ReadDir(filepath.Join(h.opts.Root, "staging"))
	for _, entry := range entries {
		t.Fatalf("tampered download left %s staged", entry.Name())
	}
}

func TestUpdateRefusesArtifactWithUnexpectedSize(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	// Same digest, different signed size: the metadata is internally
	// inconsistent, so nothing may be installed from it.
	res := runUpdate(t, h, updatePayloadJSON(map[string]any{
		"artifact": map[string]any{
			"url":        "https://releases.example/a.exe",
			"sha256":     digestOf(newBinary),
			"size_bytes": len(newBinary) + 1,
		},
	}))
	if res.Status != StatusTampered || res.Reason != "artifact_size_mismatch" {
		t.Fatalf("status=%q reason=%q, want a size refusal", res.Status, res.Reason)
	}
}

func TestUpdateSurvivesInterruptedDownload(t *testing.T) {
	h := newHarness(t, "0.1.0")
	// A transfer that dies mid-body leaves a partial staged file and an error.
	downloadArtifact = func(_ context.Context, _ string, stagingDir string, _ int64) (string, int64, string, error) {
		file, err := os.CreateTemp(stagingDir, "staged-*")
		if err != nil {
			return "", 0, "", err
		}
		file.WriteString("NEW-AGE")
		file.Close()
		return file.Name(), 0, "", fmt.Errorf("transfer interrupted: unexpected EOF")
	}
	res := runUpdate(t, h, updatePayloadJSON(nil))
	if res.Status != StatusDownloadFailed {
		t.Fatalf("status = %q, want %q", res.Status, StatusDownloadFailed)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("an interrupted download must leave the running build in place")
	}
	if journal := h.journal(); journal != nil {
		t.Fatalf("an interrupted download must not open an attempt, got state %q", journal.State)
	}
	entries, _ := os.ReadDir(filepath.Join(h.opts.Root, "staging"))
	for _, entry := range entries {
		t.Fatalf("interrupted download left %s staged", entry.Name())
	}
}

func TestHTTPDownloadRejectsOversizedBodyAndPlaintextRedirect(t *testing.T) {
	staging := t.TempDir()
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("A", 4096)))
	}))
	defer big.Close()
	if _, _, _, err := httpDownloadArtifact(context.Background(), big.URL, staging, 16); err == nil {
		t.Fatal("a body larger than the signed size must be refused")
	}

	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()
	if _, _, _, err := httpDownloadArtifact(context.Background(), notFound.URL, staging, 1024); err == nil {
		t.Fatal("a non-200 source response must be refused")
	}
}

func TestUpdateRefusesUnsignedArtifactWhenSignerIsPinned(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	verifyAuthenticode = func(context.Context, string) (bool, string, error) {
		return false, "", nil
	}
	res := runUpdate(t, h, updatePayloadJSON(map[string]any{
		"signer_thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD",
	}))
	if res.Status != StatusSignatureMismatch {
		t.Fatalf("status = %q, want %q", res.Status, StatusSignatureMismatch)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("an artifact failing the pinned signer check must not be installed")
	}
}

// --------------------------------------------------------------------------
// Staging, atomic replace, and the in-flight guard
// --------------------------------------------------------------------------

func TestUpdateStagesReplacesAndRequestsRestart(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	res := runUpdate(t, h, updatePayloadJSON(nil))

	if res.Status != StatusRestartPending {
		t.Fatalf("status = %q (%s), want %q", res.Status, res.Message, StatusRestartPending)
	}
	if !res.RestartRequested || h.restarts != 1 {
		t.Fatalf("expected exactly one restart request, got %d", h.restarts)
	}
	if h.exeContent() != newBinary {
		t.Fatal("the new build should be installed at the executable path")
	}
	journal := h.journal()
	if journal == nil || journal.State != StateInstalled {
		t.Fatalf("journal state = %v, want %q", journal, StateInstalled)
	}
	if journal.FromVersion != "0.1.0" || journal.ToVersion != "0.2.0" {
		t.Fatalf("journal versions = %s -> %s", journal.FromVersion, journal.ToVersion)
	}
	backup, err := os.ReadFile(journal.BackupPath)
	if err != nil {
		t.Fatalf("read retained backup: %v", err)
	}
	if string(backup) != oldBinary {
		t.Fatal("the retained backup must hold the previous build")
	}
	if journal.BackupSHA256 != digestOf(oldBinary) {
		t.Fatal("the retained backup digest must be journalled for the rollback check")
	}
}

func TestUpdateRefusesConcurrentAttempt(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	if res := runUpdate(t, h, updatePayloadJSON(nil)); res.Status != StatusRestartPending {
		t.Fatalf("first attempt status = %q", res.Status)
	}
	res := runUpdate(t, h, updatePayloadJSON(map[string]any{"version": "0.3.0"}))
	if res.Status != StatusUpdateInProgress {
		t.Fatalf("status = %q, want %q", res.Status, StatusUpdateInProgress)
	}
}

func TestUpdateRollsBackWhenRestartCannotBeRequested(t *testing.T) {
	h := newHarness(t, "0.1.0")
	h.serveArtifact(newBinary)
	h.restartErr = fmt.Errorf("service control manager unavailable")

	res := runUpdate(t, h, updatePayloadJSON(nil))
	if res.Status != StatusRestartFailed {
		t.Fatalf("status = %q, want %q", res.Status, StatusRestartFailed)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("a build that can never be started must be rolled back immediately")
	}
	if journal := h.journal(); journal == nil || journal.State != StateRolledBack {
		t.Fatalf("journal state = %v, want %q", journal, StateRolledBack)
	}
}

// --------------------------------------------------------------------------
// Post-restart resolution: health check, commit, and automatic rollback
// --------------------------------------------------------------------------

// stageInstalled runs an update to completion so a follow-up Resolve sees an
// installed-but-unconfirmed build, and returns the options the "new build"
// would start with.
func stageInstalled(t *testing.T, h *harness) Options {
	t.Helper()
	h.serveArtifact(newBinary)
	if res := runUpdate(t, h, updatePayloadJSON(nil)); res.Status != StatusRestartPending {
		t.Fatalf("staging failed: %s (%s)", res.Status, res.Message)
	}
	restarted := h.opts
	restarted.CurrentVersion = "0.2.0"
	return restarted
}

func TestResolveCommitsHealthyBuild(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)

	outcome, err := Resolve(context.Background(), restarted, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Status != StatusSucceeded {
		t.Fatalf("outcome = %+v, want succeeded", outcome)
	}
	if outcome.ReleaseID != "rel-0002" || outcome.ToVersion != "0.2.0" {
		t.Fatalf("outcome lost release evidence: %+v", outcome)
	}
	if h.exeContent() != newBinary {
		t.Fatal("a healthy build must stay installed")
	}
	previous, err := loadPrevious(h.opts.Root)
	if err != nil || previous == nil {
		t.Fatalf("committed update must retain the previous build: %v %v", previous, err)
	}
	if previous.Version != "0.1.0" || previous.SHA256 != digestOf(oldBinary) {
		t.Fatalf("retained previous build = %+v", previous)
	}

	// The resolved attempt is kept until the server acknowledges it.
	if journal := h.journal(); journal == nil || journal.State != StateCommitted {
		t.Fatalf("journal state = %v, want %q", journal, StateCommitted)
	}
	if err := Acknowledge(restarted); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if h.journal() != nil {
		t.Fatal("an acknowledged attempt must be cleared")
	}
}

func TestResolveRollsBackUnhealthyBuild(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)
	before := h.restarts

	outcome, err := Resolve(context.Background(), restarted, func(context.Context) error {
		return fmt.Errorf("server rejected the new build's check-in")
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Status != StatusRolledBack || outcome.Reason != "health_check_failed" {
		t.Fatalf("outcome = %+v, want a health-check rollback", outcome)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("an unhealthy build must be replaced by the retained previous build")
	}
	if h.restarts != before+1 {
		t.Fatal("a rollback must restart into the restored build")
	}
	if journal := h.journal(); journal == nil || journal.State != StateRolledBack {
		t.Fatalf("journal state = %v, want %q", journal, StateRolledBack)
	}
}

func TestResolveRollsBackWhenRestartDidNotBringUpTheNewBuild(t *testing.T) {
	h := newHarness(t, "0.1.0")
	stageInstalled(t, h)
	// The process that came back up still reports the old version: the swap or
	// the restart did not take effect.
	stale := h.opts
	stale.CurrentVersion = "0.1.0"

	outcome, err := Resolve(context.Background(), stale, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Reason != "version_mismatch_after_restart" {
		t.Fatalf("outcome = %+v, want a version-mismatch rollback", outcome)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("the retained previous build must be restored")
	}
}

func TestResolveRollsBackAfterHealthDeadline(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)
	nowUTC = func() time.Time { return time.Now().UTC().Add(2 * time.Hour) }

	outcome, err := Resolve(context.Background(), restarted, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Reason != "health_check_deadline_exceeded" {
		t.Fatalf("outcome = %+v, want a deadline rollback", outcome)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("a build that never became healthy in time must be rolled back")
	}
}

func TestResolveRollsBackAfterRepeatedUnconfirmedStarts(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)

	// Simulate a build that crashes before it can report: each start bumps the
	// attempt counter without resolving the journal.
	journal := h.journal()
	journal.Attempts = maxHealthAttempts
	if err := saveJournal(h.opts.Root, journal); err != nil {
		t.Fatal(err)
	}

	outcome, err := Resolve(context.Background(), restarted, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Reason != "health_check_attempts_exhausted" {
		t.Fatalf("outcome = %+v, want an attempts-exhausted rollback", outcome)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("a repeatedly unconfirmed build must be rolled back")
	}
}

func TestResolveWithoutHealthCheckRollsBack(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)
	outcome, err := Resolve(context.Background(), restarted, nil)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Reason != "health_check_unavailable" {
		t.Fatalf("outcome = %+v, want a fail-closed rollback", outcome)
	}
}

func TestResolveCleansUpAttemptInterruptedBeforeInstall(t *testing.T) {
	h := newHarness(t, "0.1.0")
	staging := filepath.Join(h.opts.Root, "staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(staging, "partial")
	if err := os.WriteFile(staged, []byte(newBinary), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveJournal(h.opts.Root, &Journal{
		State:          StateStaged,
		ReleaseID:      "rel-0002",
		FromVersion:    "0.1.0",
		ToVersion:      "0.2.0",
		ExePath:        h.opts.ExePath,
		BackupPath:     backupPath(h.opts, "0.1.0"),
		StagedPath:     staged,
		StartedAt:      time.Now().UTC().Format(time.RFC3339Nano),
		HealthDeadline: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	outcome, err := Resolve(context.Background(), h.opts, func(context.Context) error { return nil })
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if outcome == nil || outcome.Status != StatusFailed || outcome.Reason != "interrupted_before_install" {
		t.Fatalf("outcome = %+v, want an interrupted-before-install failure", outcome)
	}
	if _, err := os.Stat(staged); !os.IsNotExist(err) {
		t.Fatal("the abandoned staged artifact must be removed")
	}
	if h.exeContent() != oldBinary {
		t.Fatal("nothing was installed, so the running build must be untouched")
	}
}

func TestResolveIsANoOpWithoutAnAttempt(t *testing.T) {
	h := newHarness(t, "0.1.0")
	outcome, err := Resolve(context.Background(), h.opts, func(context.Context) error { return nil })
	if err != nil || outcome != nil {
		t.Fatalf("outcome=%+v err=%v, want no in-flight attempt", outcome, err)
	}
}

func TestResolveFailsClosedOnUnusableJournal(t *testing.T) {
	h := newHarness(t, "0.1.0")
	if err := os.MkdirAll(h.opts.Root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(JournalPath(h.opts.Root), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), h.opts, func(context.Context) error { return nil }); err == nil {
		t.Fatal("an unusable journal must be surfaced, not ignored silently")
	}
}

func TestAcknowledgeKeepsInFlightAttempt(t *testing.T) {
	h := newHarness(t, "0.1.0")
	stageInstalled(t, h)
	if err := Acknowledge(h.opts); err != nil {
		t.Fatalf("Acknowledge: %v", err)
	}
	if journal := h.journal(); journal == nil || journal.State != StateInstalled {
		t.Fatal("an in-flight attempt must survive an acknowledgement")
	}
}

// --------------------------------------------------------------------------
// Operator-triggered rollback
// --------------------------------------------------------------------------

func rollbackPayloadJSON(overrides map[string]any) json.RawMessage {
	payload := map[string]any{"reason": "bad release 0.2.0", "confirm": true}
	for key, value := range overrides {
		if value == nil {
			delete(payload, key)
			continue
		}
		payload[key] = value
	}
	raw, _ := json.Marshal(payload)
	return raw
}

func runRollback(t *testing.T, h *harness, opts Options, payload json.RawMessage) Result {
	t.Helper()
	return decodeResult(t, Execute(context.Background(), "cmd-2", executor.KindAgentUpdateRollback, payload, opts))
}

func TestRollbackRequiresConfirmationAndReason(t *testing.T) {
	h := newHarness(t, "0.2.0")
	for name, overrides := range map[string]map[string]any{
		"no confirmation": {"confirm": false},
		"empty reason":    {"reason": ""},
		"control chars":   {"reason": "bad\x00release"},
	} {
		t.Run(name, func(t *testing.T) {
			res := runRollback(t, h, h.opts, rollbackPayloadJSON(overrides))
			if res.Status != StatusInvalid {
				t.Fatalf("status = %q, want %q", res.Status, StatusInvalid)
			}
		})
	}
}

func TestRollbackWithoutRetainedBuildFailsClosed(t *testing.T) {
	h := newHarness(t, "0.2.0")
	res := runRollback(t, h, h.opts, rollbackPayloadJSON(nil))
	if res.Status != StatusNoPreviousBuild {
		t.Fatalf("status = %q, want %q", res.Status, StatusNoPreviousBuild)
	}
	if h.restarts != 0 {
		t.Fatal("a rollback with nothing to restore must not restart the service")
	}
}

func TestRollbackRestoresRetainedPreviousBuild(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)
	if _, err := Resolve(context.Background(), restarted, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := Acknowledge(restarted); err != nil {
		t.Fatal(err)
	}
	before := h.restarts

	res := runRollback(t, h, restarted, rollbackPayloadJSON(nil))
	if res.Status != StatusRolledBack {
		t.Fatalf("status = %q (%s), want %q", res.Status, res.Message, StatusRolledBack)
	}
	if res.ToVersion != "0.1.0" {
		t.Fatalf("rollback target = %q, want the retained 0.1.0", res.ToVersion)
	}
	if h.exeContent() != oldBinary {
		t.Fatal("the retained previous build must be installed")
	}
	if h.restarts != before+1 {
		t.Fatal("a rollback must restart into the restored build")
	}
}

func TestRollbackRefusesTamperedRetainedBuild(t *testing.T) {
	h := newHarness(t, "0.1.0")
	restarted := stageInstalled(t, h)
	if _, err := Resolve(context.Background(), restarted, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := Acknowledge(restarted); err != nil {
		t.Fatal(err)
	}
	previous, err := loadPrevious(h.opts.Root)
	if err != nil || previous == nil {
		t.Fatalf("expected a retained build: %v", err)
	}
	// Someone rewrote the retained binary on disk after it was digested.
	if err := os.WriteFile(previous.Path, []byte("ATTACKER-BINARY"), 0o700); err != nil {
		t.Fatal(err)
	}

	res := runRollback(t, h, restarted, rollbackPayloadJSON(nil))
	if res.Status != StatusFailed || res.Reason != "restore_failed" {
		t.Fatalf("status=%q reason=%q, want a digest-mismatch refusal", res.Status, res.Reason)
	}
	if h.exeContent() != newBinary {
		t.Fatal("a tampered retained build must never be installed")
	}
}

func TestRollbackHonorsVersionPrecondition(t *testing.T) {
	h := newHarness(t, "0.2.0")
	res := runRollback(t, h, h.opts, rollbackPayloadJSON(map[string]any{
		"expected_current_version": "0.9.9",
	}))
	if res.Status != StatusInvalid || res.Reason != "version_precondition_failed" {
		t.Fatalf("status=%q reason=%q, want a precondition refusal", res.Status, res.Reason)
	}
}

// --------------------------------------------------------------------------
// Misc contract checks
// --------------------------------------------------------------------------

func TestExecuteRejectsUnsupportedKind(t *testing.T) {
	h := newHarness(t, "0.1.0")
	res := decodeResult(t, Execute(context.Background(), "cmd-3", executor.KindPowerShell, updatePayloadJSON(nil), h.opts))
	if res.Status != StatusUnsupported {
		t.Fatalf("status = %q, want %q", res.Status, StatusUnsupported)
	}
}

func TestExecuteFailsClosedWhenEndpointStateIsUnknown(t *testing.T) {
	res := decodeResult(t, Execute(context.Background(), "cmd-4", executor.KindAgentSelfUpdate, updatePayloadJSON(nil), Options{
		CurrentVersion: "0.1.0",
		Platform:       "windows/amd64",
		// No executable path: nothing can be replaced safely.
	}))
	if res.Status != StatusInvalid {
		t.Fatalf("status = %q, want %q", res.Status, StatusInvalid)
	}
}

func TestExecuteRefusesUnstampedRunningVersion(t *testing.T) {
	h := newHarness(t, "0.1.0")
	unstamped := h.opts
	unstamped.CurrentVersion = "not-a-version"
	res := decodeResult(t, Execute(context.Background(), "cmd-5", executor.KindAgentSelfUpdate, updatePayloadJSON(nil), unstamped))
	if res.Status != StatusInvalid {
		t.Fatalf("status = %q, want %q", res.Status, StatusInvalid)
	}
}

func TestDefaultRootSitsNextToTheExecutable(t *testing.T) {
	got := DefaultRoot(filepath.Join("C:", "Program Files", "NodeLink", "rmm-agent.exe"))
	want := filepath.Join("C:", "Program Files", "NodeLink", updateDirName)
	if got != want {
		t.Fatalf("DefaultRoot = %q, want %q", got, want)
	}
}
