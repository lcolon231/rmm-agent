// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

// seams bundles the swappable platform/network functions for a test.
type seams struct {
	download  func(context.Context, string, int64) (string, int64, string, error)
	auth      func(context.Context, string) (bool, string, error)
	run       func(context.Context, string, string, []string, time.Duration) (int, error)
	product   func(context.Context, string) string
	reboot    func(context.Context, int, string) (string, string, error)
	activeUsr func(context.Context) (string, error)
}

func withSeams(t *testing.T, s seams) {
	t.Helper()
	od, oa, or, op, orb, ou := downloadInstaller, verifyAuthenticode, runInstaller, readProductCode, scheduleReboot, activeUser
	if s.download != nil {
		downloadInstaller = s.download
	}
	if s.auth != nil {
		verifyAuthenticode = s.auth
	}
	if s.run != nil {
		runInstaller = s.run
	}
	if s.product != nil {
		readProductCode = s.product
	}
	if s.reboot != nil {
		scheduleReboot = s.reboot
	}
	if s.activeUsr != nil {
		activeUser = s.activeUsr
	}
	t.Cleanup(func() {
		downloadInstaller, verifyAuthenticode, runInstaller, readProductCode, scheduleReboot, activeUser = od, oa, or, op, orb, ou
	})
}

const goodSHA = "1111111111111111111111111111111111111111111111111111111111111111"

func fakeDownload(sha string) func(context.Context, string, int64) (string, int64, string, error) {
	return func(_ context.Context, _ string, _ int64) (string, int64, string, error) {
		return "", 4096, sha, nil
	}
}

func msiPayload(overrides map[string]any) json.RawMessage {
	p := map[string]any{
		"url":             "https://cdn.example/app.msi",
		"sha256":          goodSHA,
		"installer_type":  "msi",
		"timeout_seconds": 600,
	}
	for k, v := range overrides {
		p[k] = v
	}
	raw, _ := json.Marshal(p)
	return raw
}

func decode(t *testing.T, res executor.Result) Result {
	t.Helper()
	var out Result
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("stdout not Result JSON: %v (%s)", err, res.Stdout)
	}
	return out
}

func TestDeploySuccess(t *testing.T) {
	withSeams(t, seams{
		download: fakeDownload(goodSHA),
		run:      func(context.Context, string, string, []string, time.Duration) (int, error) { return 0, nil },
		product:  func(context.Context, string) string { return "{PRODUCT-CODE}" },
	})
	res := Execute(context.Background(), executor.KindDeploySoftware, msiPayload(nil))
	if res.ExitCode != 0 {
		t.Fatalf("exit=%d stderr=%s", res.ExitCode, res.Stderr)
	}
	out := decode(t, res)
	if out.Status != "succeeded" || out.ProductCode != "{PRODUCT-CODE}" {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestDeployTamperedDigestFailsClosed(t *testing.T) {
	ran := false
	withSeams(t, seams{
		download: fakeDownload("2222222222222222222222222222222222222222222222222222222222222222"),
		run:      func(context.Context, string, string, []string, time.Duration) (int, error) { ran = true; return 0, nil },
	})
	res := Execute(context.Background(), executor.KindDeploySoftware, msiPayload(nil))
	if res.ExitCode == 0 {
		t.Fatal("digest mismatch must fail")
	}
	if ran {
		t.Fatal("installer must not run on digest mismatch")
	}
	if decode(t, res).Status != "tampered" {
		t.Fatalf("want tampered, got %s", res.Stdout)
	}
}

func TestDeploySignerMismatch(t *testing.T) {
	withSeams(t, seams{
		download: fakeDownload(goodSHA),
		auth:     func(context.Context, string) (bool, string, error) { return true, "BADTHUMBPRINT", nil },
		run:      func(context.Context, string, string, []string, time.Duration) (int, error) { return 0, nil },
	})
	payload := msiPayload(map[string]any{"signer_thumbprint": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
	res := Execute(context.Background(), executor.KindDeploySoftware, payload)
	if decode(t, res).Status != "signature_mismatch" {
		t.Fatalf("want signature_mismatch, got %s", res.Stdout)
	}
}

func TestDeployRebootRequiredExitCode(t *testing.T) {
	withSeams(t, seams{
		download: fakeDownload(goodSHA),
		run:      func(context.Context, string, string, []string, time.Duration) (int, error) { return 3010, nil },
		product:  func(context.Context, string) string { return "" },
	})
	res := Execute(context.Background(), executor.KindDeploySoftware, msiPayload(nil))
	out := decode(t, res)
	if out.Status != "succeeded_reboot_required" || !out.RebootRequired {
		t.Fatalf("3010 should be success+reboot: %+v", out)
	}
}

func TestDeployFailureExitCode(t *testing.T) {
	withSeams(t, seams{
		download: fakeDownload(goodSHA),
		run:      func(context.Context, string, string, []string, time.Duration) (int, error) { return 1603, nil },
	})
	res := Execute(context.Background(), executor.KindDeploySoftware, msiPayload(nil))
	if res.ExitCode != 1 || decode(t, res).Status != "failed" {
		t.Fatalf("1603 should be a failure: exit=%d %s", res.ExitCode, res.Stdout)
	}
}

func TestDeploySuccessExitCodeOverride(t *testing.T) {
	withSeams(t, seams{
		download: fakeDownload(goodSHA),
		run:      func(context.Context, string, string, []string, time.Duration) (int, error) { return 42, nil },
		product:  func(context.Context, string) string { return "" },
	})
	res := Execute(context.Background(), executor.KindDeploySoftware,
		msiPayload(map[string]any{"success_exit_codes": []int{0, 42}}))
	if decode(t, res).Status != "succeeded" {
		t.Fatalf("42 should be success via override: %s", res.Stdout)
	}
}

func TestDeployTimeoutMappedFromRunError(t *testing.T) {
	withSeams(t, seams{
		download: fakeDownload(goodSHA),
		run: func(context.Context, string, string, []string, time.Duration) (int, error) {
			return -1, fmt.Errorf("installer timed out after 10m0s")
		},
	})
	res := Execute(context.Background(), executor.KindDeploySoftware, msiPayload(nil))
	if res.ExitCode == 0 || decode(t, res).Status != "run_failed" {
		t.Fatalf("timeout should be run_failed: %s", res.Stdout)
	}
}

func TestDeployRebootDeferredWhenUserPresent(t *testing.T) {
	scheduled := false
	withSeams(t, seams{
		download:  fakeDownload(goodSHA),
		run:       func(context.Context, string, string, []string, time.Duration) (int, error) { return 3010, nil },
		product:   func(context.Context, string) string { return "" },
		activeUsr: func(context.Context) (string, error) { return "DOMAIN\\alice", nil },
		reboot: func(context.Context, int, string) (string, string, error) {
			scheduled = true
			return "scheduled", "", nil
		},
	})
	payload := msiPayload(map[string]any{
		"reboot": map[string]any{"policy": "forced", "delay_seconds": 300, "requires_no_user": true},
	})
	out := decode(t, Execute(context.Background(), executor.KindDeploySoftware, payload))
	if out.Reboot == nil || out.Reboot.Decision != "deferred_user_present" {
		t.Fatalf("reboot should defer with a user present: %+v", out.Reboot)
	}
	if scheduled {
		t.Fatal("reboot must not be scheduled while a user is present")
	}
}

func TestDeployRebootScheduledWhenNoUser(t *testing.T) {
	scheduled := false
	withSeams(t, seams{
		download:  fakeDownload(goodSHA),
		run:       func(context.Context, string, string, []string, time.Duration) (int, error) { return 3010, nil },
		product:   func(context.Context, string) string { return "" },
		activeUsr: func(context.Context) (string, error) { return "", nil },
		reboot: func(context.Context, int, string) (string, string, error) {
			scheduled = true
			return "scheduled", "", nil
		},
	})
	payload := msiPayload(map[string]any{
		"reboot": map[string]any{"policy": "if_required", "delay_seconds": 300, "requires_no_user": true},
	})
	out := decode(t, Execute(context.Background(), executor.KindDeploySoftware, payload))
	if out.Reboot == nil || out.Reboot.Decision != "scheduled" || !scheduled {
		t.Fatalf("reboot should schedule with no user: %+v scheduled=%v", out.Reboot, scheduled)
	}
}

func TestDeployRejectsInvalidPayloads(t *testing.T) {
	cases := []map[string]any{
		{"url": "http://cdn.example/app.msi"}, // not https
		{"sha256": "nothex"},                  // bad digest
		{"installer_type": "deb"},             // bad type
		{"timeout_seconds": 5},                // below min
		{"timeout_seconds": 99999},            // above max
		{"extra": true},                       // unknown field
		{"signer_thumbprint": "short"},        // bad thumbprint
	}
	for _, override := range cases {
		res := Execute(context.Background(), executor.KindDeploySoftware, msiPayload(override))
		if res.ExitCode == 0 {
			t.Fatalf("payload should be rejected: %v", override)
		}
	}
}

// ---- downloader (real HTTP via httptest) ----

func TestHTTPDownloadComputesDigestAndSize(t *testing.T) {
	body := []byte("installer-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	path, size, sha, err := httpDownloadInstaller(context.Background(), srv.URL, MaxInstallerBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer removeIfExists(path)
	sum := sha256.Sum256(body)
	if sha != hex.EncodeToString(sum[:]) || size != int64(len(body)) {
		t.Fatalf("digest/size mismatch: %s %d", sha, size)
	}
}

func TestHTTPDownloadEnforcesSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer srv.Close()

	path, _, _, err := httpDownloadInstaller(context.Background(), srv.URL, 1024)
	defer removeIfExists(path)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected size-limit error, got %v", err)
	}
}

func TestHTTPDownloadRefusesNonHTTPSRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound) // http:// target
	}))
	defer redirector.Close()

	_, _, _, err := httpDownloadInstaller(context.Background(), redirector.URL, MaxInstallerBytes)
	if err == nil || !strings.Contains(err.Error(), "non-https") {
		t.Fatalf("expected non-https redirect refusal, got %v", err)
	}
}

func removeIfExists(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}
