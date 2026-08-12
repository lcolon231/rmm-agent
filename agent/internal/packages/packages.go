// SPDX-License-Identifier: AGPL-3.0-only
// Package packages implements the typed, signed package-provider contract
// introduced by issue #55: bounded discovery (installed + upgradable) and
// install/upgrade of an explicit set of packages via a chosen provider. Winget
// is the always-available default; Chocolatey is reachable only when the
// operator has opted the endpoint in and the server supplies signed source,
// digest, and signer evidence, which the agent re-validates here at the
// endpoint before ever invoking the provider.
package packages

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/inventory"
)

// Provider names. These are the wire values the server validates against.
const (
	ProviderWinget     = "winget"
	ProviderChocolatey = "chocolatey"
)

// Operations. Install adds a package; upgrade moves an installed package to a
// newer version. Both are idempotent per package: a provider that reports "no
// applicable update" is a success, not a failure.
const (
	OperationInstall = "install"
	OperationUpgrade = "upgrade"
)

// MaxPackageTargets bounds a single install/upgrade command, matching the
// Windows Update install bound so one command cannot fan out without limit.
const MaxPackageTargets = 100

// SectionInstalledPackages is the inventory section name a scan result is
// reported under. It mirrors the server's InventorySection.installed_packages.
const SectionInstalledPackages = "installed_packages"

var (
	// packageIDPattern accepts winget/msstore/chocolatey identifiers: a leading
	// alphanumeric then a bounded run of the punctuation those ecosystems use.
	packageIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	// sourceDigestPattern is a lowercase SHA-256 hex digest of the provider source.
	sourceDigestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config gates the optional Chocolatey provider at the endpoint. It is derived
// from the agent's install-time configuration and passed to every command so a
// disabled provider fails closed even if the server dispatched the command.
type Config struct {
	ChocolateyEnabled bool
	ChocolateySources []string
}

// installPayload is the strict shape of an install_packages command payload.
type installPayload struct {
	Provider     string   `json:"provider"`
	Operation    string   `json:"operation"`
	PackageIDs   []string `json:"package_ids"`
	Source       string   `json:"source,omitempty"`
	SourceDigest string   `json:"source_digest,omitempty"`
	Signer       string   `json:"signer,omitempty"`
}

// scanPayload is the strict shape of a scan_packages command payload. Provider
// is optional; empty means "every enabled provider".
type scanPayload struct {
	Provider string `json:"provider,omitempty"`
}

// PackageOutcome is the per-package result of an install/upgrade attempt.
type PackageOutcome struct {
	PackageID  string `json:"package_id"`
	Operation  string `json:"operation"`
	ResultCode int    `json:"result_code"`
	Version    string `json:"version,omitempty"`
	Message    string `json:"message,omitempty"`
}

// InstallResult is the JSON evidence reported in the command's stdout.
type InstallResult struct {
	Status         string           `json:"status"`
	Provider       string           `json:"provider"`
	Operation      string           `json:"operation"`
	SourceDigest   string           `json:"source_digest,omitempty"`
	Installed      []string         `json:"installed"`
	Failed         []string         `json:"failed"`
	Results        []PackageOutcome `json:"results,omitempty"`
	RebootRequired bool             `json:"reboot_required"`
	Message        string           `json:"message"`
}

// InstalledPackage is one discovered installed package.
type InstalledPackage struct {
	PackageID string `json:"package_id"`
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
}

// UpgradablePackage is one discovered package with an available upgrade.
type UpgradablePackage struct {
	PackageID        string `json:"package_id"`
	Name             string `json:"name,omitempty"`
	CurrentVersion   string `json:"current_version,omitempty"`
	AvailableVersion string `json:"available_version,omitempty"`
	Source           string `json:"source,omitempty"`
}

// ScanResult is the normalized discovery result for one provider.
type ScanResult struct {
	Provider   string              `json:"provider"`
	Status     string              `json:"status"`
	ScannedAt  time.Time           `json:"scanned_at"`
	Installed  []InstalledPackage  `json:"installed"`
	Upgradable []UpgradablePackage `json:"upgradable"`
	ErrorCode  string              `json:"error_code,omitempty"`
}

// ScanSummary is the small command-output projection of a scan.
type ScanSummary struct {
	Status          string `json:"status"`
	Provider        string `json:"provider"`
	InstalledCount  int    `json:"installed_count"`
	UpgradableCount int    `json:"upgradable_count"`
	ErrorCode       string `json:"error_code,omitempty"`
	Message         string `json:"message,omitempty"`
}

// Function seams keep the platform providers mockable. Tests reassign these so a
// unit test never shells out to winget.exe or choco.exe.
var (
	wingetDiscover = platformWingetDiscover
	wingetInstall  = platformWingetInstall
	chocoDiscover  = platformChocoDiscover
	chocoInstall   = platformChocoInstall
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

func resultError(status, provider, operation, digest, message string) executor.Result {
	out, _ := json.Marshal(InstallResult{
		Status:       status,
		Provider:     provider,
		Operation:    operation,
		SourceDigest: digest,
		Installed:    []string{},
		Failed:       []string{},
		Message:      message,
	})
	return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: message}
}

// normalizePackageIDs validates, trims, and deduplicates the target list while
// preserving order. The bound and per-value pattern fail closed on anything odd.
func normalizePackageIDs(ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("at least one package_id is required")
	}
	if len(ids) > MaxPackageTargets {
		return nil, fmt.Errorf("at most %d package targets are allowed", MaxPackageTargets)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, value := range ids {
		id := strings.TrimSpace(value)
		if !packageIDPattern.MatchString(id) {
			return nil, fmt.Errorf("invalid package_id %q", value)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// validateChocolateyEvidence re-checks, at the endpoint, that the server
// supplied the signed source/digest/signer this endpoint requires before a
// Chocolatey install may run. It fails closed on any missing or unexpected value.
func validateChocolateyEvidence(p installPayload, cfg Config) error {
	if !cfg.ChocolateyEnabled {
		return fmt.Errorf("chocolatey provider is not enabled on this endpoint")
	}
	source := strings.TrimSpace(p.Source)
	if source == "" || len(source) > 512 || strings.IndexFunc(source, isControl) >= 0 {
		return fmt.Errorf("chocolatey source is missing or invalid")
	}
	if !sourceDigestPattern.MatchString(p.SourceDigest) {
		return fmt.Errorf("chocolatey source_digest must be a sha256 hex digest")
	}
	signer := strings.TrimSpace(p.Signer)
	if signer == "" || len(signer) > 255 || strings.IndexFunc(signer, isControl) >= 0 {
		return fmt.Errorf("chocolatey signer is missing or invalid")
	}
	if len(cfg.ChocolateySources) > 0 {
		allowed := false
		for _, candidate := range cfg.ChocolateySources {
			if strings.EqualFold(strings.TrimSpace(candidate), source) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("chocolatey source is not in the endpoint allowlist")
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 32 || r == 127 }

// ExecuteInstall runs one install_packages command and returns JSON evidence.
// The caller has already durably journaled the command; this re-validates the
// entire signed payload again at the endpoint before invoking a provider.
func ExecuteInstall(ctx context.Context, kind string, raw json.RawMessage, cfg Config) executor.Result {
	if kind != executor.KindInstallPackages {
		return resultError("unsupported", "", "", "", "unsupported package operation")
	}
	var p installPayload
	if err := decodeStrict(raw, &p); err != nil {
		return resultError("invalid", "", "", "", "install_packages payload is invalid")
	}
	if p.Operation != OperationInstall && p.Operation != OperationUpgrade {
		return resultError("invalid", p.Provider, p.Operation, "", "install_packages operation is invalid")
	}
	if p.Provider != ProviderWinget && p.Provider != ProviderChocolatey {
		return resultError("invalid", p.Provider, p.Operation, "", "install_packages provider is unsupported")
	}
	ids, err := normalizePackageIDs(p.PackageIDs)
	if err != nil {
		return resultError("invalid", p.Provider, p.Operation, "", "install_packages targets are invalid: "+err.Error())
	}

	var install func(context.Context, string, []string) ([]PackageOutcome, error)
	digest := ""
	switch p.Provider {
	case ProviderWinget:
		// Winget must not carry Chocolatey-only source evidence.
		if p.Source != "" || p.SourceDigest != "" || p.Signer != "" {
			return resultError("invalid", p.Provider, p.Operation, "", "winget install must not include source evidence")
		}
		install = wingetInstall
	case ProviderChocolatey:
		if err := validateChocolateyEvidence(p, cfg); err != nil {
			return resultError("refused", p.Provider, p.Operation, p.SourceDigest, "chocolatey install refused: "+err.Error())
		}
		digest = p.SourceDigest
		install = chocoInstall
	}

	outcomes, err := install(ctx, p.Operation, ids)
	res := assembleInstallResult(p.Provider, p.Operation, digest, ids, outcomes)
	if err != nil {
		outBytes, _ := json.Marshal(res)
		return executor.Result{ExitCode: -1, Stdout: string(outBytes), Stderr: p.Provider + " install failed: " + err.Error()}
	}
	outBytes, _ := json.Marshal(res)
	exitCode := 0
	if res.Status == "failed" {
		exitCode = 1
	}
	return executor.Result{ExitCode: exitCode, Stdout: string(outBytes)}
}

// assembleInstallResult classifies per-package outcomes into a bounded result.
// A result code of 0 is success; anything else is a failure for that package.
func assembleInstallResult(provider, operation, digest string, ids []string, outcomes []PackageOutcome) InstallResult {
	res := InstallResult{
		Provider:     provider,
		Operation:    operation,
		SourceDigest: digest,
		Installed:    []string{},
		Failed:       []string{},
	}
	byID := map[string]PackageOutcome{}
	for _, outcome := range outcomes {
		byID[outcome.PackageID] = outcome
		res.Results = append(res.Results, outcome)
		if outcome.ResultCode == 0 {
			res.Installed = append(res.Installed, outcome.PackageID)
		} else {
			res.Failed = append(res.Failed, outcome.PackageID)
		}
	}
	// A requested id with no reported outcome counts as a failure so a silently
	// dropped target is never presented as a success.
	for _, id := range ids {
		if _, ok := byID[id]; !ok {
			res.Failed = append(res.Failed, id)
			res.Results = append(res.Results, PackageOutcome{
				PackageID: id, Operation: operation, ResultCode: -1, Message: "no outcome reported",
			})
		}
	}
	switch {
	case len(res.Failed) == 0:
		res.Status = "success"
	case len(res.Installed) == 0:
		res.Status = "failed"
	default:
		res.Status = "partial"
	}
	return res
}

// Scan runs a bounded discovery for the requested provider (or every enabled
// provider when unspecified) and returns the merged, normalized result. It is
// pure orchestration over the platform seams so tests never shell out.
func Scan(ctx context.Context, raw json.RawMessage, cfg Config) (ScanResult, error) {
	var p scanPayload
	if len(raw) > 0 {
		if err := decodeStrict(raw, &p); err != nil {
			return ScanResult{}, fmt.Errorf("scan_packages payload is invalid")
		}
	}
	provider := p.Provider
	if provider == "" {
		provider = ProviderWinget
	}
	if provider != ProviderWinget && provider != ProviderChocolatey {
		return ScanResult{}, fmt.Errorf("scan_packages provider is unsupported")
	}
	if provider == ProviderChocolatey && !cfg.ChocolateyEnabled {
		return ScanResult{}, fmt.Errorf("chocolatey provider is not enabled on this endpoint")
	}

	discover := wingetDiscover
	if provider == ProviderChocolatey {
		discover = chocoDiscover
	}
	installed, upgradable, err := discover(ctx)
	result := ScanResult{
		Provider:   provider,
		ScannedAt:  time.Now().UTC(),
		Installed:  installed,
		Upgradable: upgradable,
		Status:     inventory.StatusOK,
	}
	if err != nil {
		result.Status = inventory.StatusUnavailable
		result.ErrorCode = err.Error()
		return result, err
	}
	return result, nil
}

// BuildSection turns a scan result into the installed_packages inventory
// section. It is pure and platform-independent so it can be tested with
// fixtures, mirroring patching.BuildSection.
func BuildSection(result ScanResult) inventory.Section {
	installed := make([]map[string]any, 0, len(result.Installed))
	for _, pkg := range result.Installed {
		installed = append(installed, map[string]any{
			"package_id": pkg.PackageID,
			"name":       pkg.Name,
			"version":    pkg.Version,
			"source":     pkg.Source,
		})
	}
	upgradable := make([]map[string]any, 0, len(result.Upgradable))
	for _, pkg := range result.Upgradable {
		upgradable = append(upgradable, map[string]any{
			"package_id":        pkg.PackageID,
			"name":              pkg.Name,
			"current_version":   pkg.CurrentVersion,
			"available_version": pkg.AvailableVersion,
			"source":            pkg.Source,
		})
	}
	payload := map[string]any{
		"scanned_at": result.ScannedAt.UTC().Format(time.RFC3339Nano),
		"source":     result.Provider,
		"installed":  installed,
		"upgradable": upgradable,
	}
	if result.ErrorCode != "" {
		payload["error_code"] = result.ErrorCode
	}
	return inventory.Section{
		Section:     SectionInstalledPackages,
		Status:      result.Status,
		CollectedAt: result.ScannedAt.UTC(),
		Payload:     payload,
	}
}

// Summarize projects a scan result into the small command-output summary.
func Summarize(result ScanResult) ScanSummary {
	return ScanSummary{
		Status:          result.Status,
		Provider:        result.Provider,
		InstalledCount:  len(result.Installed),
		UpgradableCount: len(result.Upgradable),
		ErrorCode:       result.ErrorCode,
	}
}
