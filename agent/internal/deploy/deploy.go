// SPDX-License-Identifier: AGPL-3.0-only
// Package deploy implements the typed MSI/EXE software-deployment contract
// introduced by issue #56. It downloads an installer over HTTPS into a bounded
// temp file, verifies its SHA-256 (and, when requested, its Authenticode
// signer), runs it under a bounded argument policy and timeout, maps the exit
// code, applies a reboot policy, and reports rollback metadata. The server has
// already validated and signed the payload; the agent re-validates structurally
// at the endpoint and fails closed on any integrity failure. It never accepts
// script text.
package deploy

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
	"regexp"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/patching"
	"github.com/lcolon231/rmm/agent/internal/power"
)

const (
	InstallerMSI = "msi"
	InstallerEXE = "exe"

	// MaxInstallerBytes bounds a downloaded installer so a hostile or misconfigured
	// source cannot exhaust the endpoint's disk.
	MaxInstallerBytes = 1 << 30 // 1 GiB
	// MaxArguments and MaxArgumentLen bound the installer argument policy.
	MaxArguments   = 32
	MaxArgumentLen = 256
	// Timeout bounds.
	minTimeoutSeconds = 30
	maxTimeoutSeconds = 3600
	// Redirect bound for the download.
	maxRedirects = 5
	// downloadTimeout bounds the HTTPS transfer independently of the install run.
	downloadTimeout = 30 * time.Minute
)

var (
	sha256Pattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	thumbprintPattern = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
	// argumentPattern rejects control characters; installers run as argv (no shell)
	// so quoting is not a concern, but bounded printable text keeps evidence clean.
	controlChar = func(r rune) bool { return r < 32 || r == 127 }
)

// Windows Installer / setup exit codes that mean "succeeded, reboot required".
var rebootExitCodes = map[int]bool{1641: true, 3010: true}

type rebootPolicy struct {
	Policy         string `json:"policy"`
	DelaySeconds   int    `json:"delay_seconds"`
	RequiresNoUser bool   `json:"requires_no_user"`
}

type deployPayload struct {
	URL              string        `json:"url"`
	SHA256           string        `json:"sha256"`
	InstallerType    string        `json:"installer_type"`
	Arguments        []string      `json:"arguments,omitempty"`
	SignerThumbprint string        `json:"signer_thumbprint,omitempty"`
	TimeoutSeconds   int           `json:"timeout_seconds"`
	SuccessExitCodes []int         `json:"success_exit_codes,omitempty"`
	Reboot           *rebootPolicy `json:"reboot,omitempty"`
}

// Result is the JSON evidence reported in the command's stdout. It carries only
// accountable metadata: digests, exit code, outcome, and rollback hints — never
// the installer bytes or the source URL in the clear.
type Result struct {
	Status          string         `json:"status"`
	InstallerType   string         `json:"installer_type"`
	SHA256          string         `json:"sha256"`
	DownloadedBytes int64          `json:"downloaded_bytes,omitempty"`
	ExitCode        int            `json:"exit_code"`
	RebootRequired  bool           `json:"reboot_required"`
	ProductCode     string         `json:"product_code,omitempty"`
	Reboot          *RebootOutcome `json:"reboot,omitempty"`
	Message         string         `json:"message,omitempty"`
}

// RebootOutcome mirrors the post-install reboot decision shape used by patching.
type RebootOutcome struct {
	Policy       string `json:"policy"`
	Decision     string `json:"decision"`
	DelaySeconds int    `json:"delay_seconds,omitempty"`
}

// Function seams keep platform calls and the network mockable in tests.
var (
	downloadInstaller  = httpDownloadInstaller
	verifyAuthenticode = platformVerifyAuthenticode
	runInstaller       = platformRunInstaller
	readProductCode    = platformReadProductCode
	scheduleReboot     = power.ScheduleReboot
	activeUser         = power.ActiveUser
)

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

func resultError(status, installerType, sha, message string) executor.Result {
	out, _ := json.Marshal(Result{
		Status: status, InstallerType: installerType, SHA256: sha, Message: message,
	})
	return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: message}
}

// validate checks the fully-decoded payload structurally. The server has already
// validated it; this is the fail-closed endpoint re-check.
func validate(p deployPayload) error {
	parsed, err := url.Parse(p.URL)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return fmt.Errorf("url must be a valid https URL")
	}
	if !sha256Pattern.MatchString(p.SHA256) {
		return fmt.Errorf("sha256 must be a lowercase SHA-256 digest")
	}
	if p.InstallerType != InstallerMSI && p.InstallerType != InstallerEXE {
		return fmt.Errorf("installer_type must be msi or exe")
	}
	if p.TimeoutSeconds < minTimeoutSeconds || p.TimeoutSeconds > maxTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between %d and %d", minTimeoutSeconds, maxTimeoutSeconds)
	}
	if len(p.Arguments) > MaxArguments {
		return fmt.Errorf("at most %d arguments are allowed", MaxArguments)
	}
	for _, arg := range p.Arguments {
		if len(arg) > MaxArgumentLen || strings.IndexFunc(arg, controlChar) >= 0 {
			return fmt.Errorf("installer argument is invalid")
		}
	}
	if p.SignerThumbprint != "" && !thumbprintPattern.MatchString(p.SignerThumbprint) {
		return fmt.Errorf("signer_thumbprint must be a 40-char hex thumbprint")
	}
	for _, code := range p.SuccessExitCodes {
		if code < 0 || code > 65535 {
			return fmt.Errorf("success_exit_codes must be 0-65535")
		}
	}
	if p.Reboot != nil {
		if p.Reboot.Policy != "never" && p.Reboot.Policy != "if_required" && p.Reboot.Policy != "forced" {
			return fmt.Errorf("reboot policy is invalid")
		}
		if p.Reboot.Policy != "never" && (p.Reboot.DelaySeconds < 60 || p.Reboot.DelaySeconds > 3600) {
			return fmt.Errorf("reboot delay_seconds must be between 60 and 3600")
		}
	}
	return nil
}

// Execute runs one deploy_software command and returns JSON evidence.
func Execute(ctx context.Context, kind string, raw json.RawMessage) executor.Result {
	if kind != executor.KindDeploySoftware {
		return resultError("unsupported", "", "", "unsupported deployment operation")
	}
	var p deployPayload
	if err := decodeStrict(raw, &p); err != nil {
		return resultError("invalid", "", "", "deploy_software payload is invalid")
	}
	if err := validate(p); err != nil {
		return resultError("invalid", p.InstallerType, p.SHA256, "deploy_software payload is invalid: "+err.Error())
	}

	// 1. Download to a bounded temp file, computing the digest as we stream.
	path, size, gotSHA, err := downloadInstaller(ctx, p.URL, MaxInstallerBytes)
	if path != "" {
		defer os.Remove(path)
	}
	if err != nil {
		return resultError("download_failed", p.InstallerType, p.SHA256, "installer download failed: "+err.Error())
	}

	// 2. Integrity: the digest is mandatory and fails closed on mismatch.
	if gotSHA != p.SHA256 {
		return resultError("tampered", p.InstallerType, p.SHA256,
			fmt.Sprintf("installer digest mismatch: expected %s, got %s", p.SHA256, gotSHA))
	}

	// 3. Optional Authenticode signer check.
	if p.SignerThumbprint != "" {
		okSig, gotThumb, sigErr := verifyAuthenticode(ctx, path)
		if sigErr != nil {
			return resultError("signature_unavailable", p.InstallerType, p.SHA256, "authenticode verification failed: "+sigErr.Error())
		}
		if !okSig || !strings.EqualFold(gotThumb, p.SignerThumbprint) {
			return resultError("signature_mismatch", p.InstallerType, p.SHA256,
				"installer signer did not match the expected Authenticode thumbprint")
		}
	}

	// 4. Run the installer under the signed timeout.
	exitCode, runErr := runInstaller(ctx, p.InstallerType, path, p.Arguments, time.Duration(p.TimeoutSeconds)*time.Second)

	res := Result{
		InstallerType:   p.InstallerType,
		SHA256:          p.SHA256,
		DownloadedBytes: size,
		ExitCode:        exitCode,
	}
	if runErr != nil {
		res.Status = "run_failed"
		res.Message = runErr.Error()
		out, _ := json.Marshal(res)
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: "installer run failed: " + runErr.Error()}
	}

	// 5. Map the exit code to an outcome.
	res.RebootRequired = rebootExitCodes[exitCode]
	switch {
	case isSuccess(exitCode, p.SuccessExitCodes):
		res.Status = "succeeded"
		if res.RebootRequired {
			res.Status = "succeeded_reboot_required"
		}
	default:
		res.Status = "failed"
		res.Message = fmt.Sprintf("installer exited with code %d", exitCode)
	}

	// 6. Rollback metadata: the MSI ProductCode lets an operator uninstall later.
	if res.Status != "failed" && p.InstallerType == InstallerMSI {
		res.ProductCode = readProductCode(ctx, path)
	}

	// 7. Reboot policy (reuses the post-install reboot mechanism of issue #53).
	if res.Status != "failed" && p.Reboot != nil && p.Reboot.Policy != "never" {
		applyReboot(ctx, &res, p.Reboot)
	}

	out, _ := json.Marshal(res)
	exit := 0
	if res.Status == "failed" {
		exit = 1
	}
	return executor.Result{ExitCode: exit, Stdout: string(out)}
}

// isSuccess treats 0 as success by default; an explicit success_exit_codes list
// replaces that default. Reboot-required codes are always a success.
func isSuccess(exitCode int, successCodes []int) bool {
	if rebootExitCodes[exitCode] {
		return true
	}
	if len(successCodes) == 0 {
		return exitCode == 0
	}
	for _, code := range successCodes {
		if code == exitCode {
			return true
		}
	}
	return false
}

func applyReboot(ctx context.Context, res *Result, policy *rebootPolicy) {
	user, _ := activeUser(ctx)
	decision := patching.DecideReboot(patching.RebootDecisionInput{
		Policy:         policy.Policy,
		RequiresNoUser: policy.RequiresNoUser,
		RebootRequired: res.RebootRequired,
		ActiveUser:     user,
	})
	res.Reboot = &RebootOutcome{
		Policy:       policy.Policy,
		Decision:     decision,
		DelaySeconds: policy.DelaySeconds,
	}
	if decision == patching.RebootScheduled {
		if _, _, err := scheduleReboot(ctx, policy.DelaySeconds, "NodeLink post-deployment reboot"); err != nil {
			res.Reboot.Decision = "schedule_failed"
		}
	}
}

// httpDownloadInstaller streams an HTTPS URL to a temp file, enforcing a byte
// cap and refusing any redirect that leaves HTTPS (no downgrade to plaintext).
// It returns the temp path, the byte count, and the lowercase SHA-256 digest.
func httpDownloadInstaller(ctx context.Context, rawURL string, maxBytes int64) (string, int64, string, error) {
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

	tmp, err := os.CreateTemp("", "nodelink-deploy-*.installer")
	if err != nil {
		return "", 0, "", err
	}
	path := tmp.Name()
	hasher := sha256.New()
	// Read one extra byte so an over-cap body is detected rather than silently cut.
	limited := io.LimitReader(resp.Body, maxBytes+1)
	written, err := io.Copy(io.MultiWriter(tmp, hasher), limited)
	closeErr := tmp.Close()
	if err != nil {
		return path, 0, "", err
	}
	if closeErr != nil {
		return path, 0, "", closeErr
	}
	if written > maxBytes {
		return path, 0, "", fmt.Errorf("installer exceeds the %d-byte limit", maxBytes)
	}
	return path, written, hex.EncodeToString(hasher.Sum(nil)), nil
}
