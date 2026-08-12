// SPDX-License-Identifier: AGPL-3.0-only
package packages

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

// withSeams swaps the platform seams for the duration of a test.
func withSeams(t *testing.T,
	wInstall func(context.Context, string, []string) ([]PackageOutcome, error),
	cInstall func(context.Context, string, []string) ([]PackageOutcome, error),
	wDiscover func(context.Context) ([]InstalledPackage, []UpgradablePackage, error),
	cDiscover func(context.Context) ([]InstalledPackage, []UpgradablePackage, error),
) {
	t.Helper()
	origWI, origCI, origWD, origCD := wingetInstall, chocoInstall, wingetDiscover, chocoDiscover
	if wInstall != nil {
		wingetInstall = wInstall
	}
	if cInstall != nil {
		chocoInstall = cInstall
	}
	if wDiscover != nil {
		wingetDiscover = wDiscover
	}
	if cDiscover != nil {
		chocoDiscover = cDiscover
	}
	t.Cleanup(func() {
		wingetInstall, chocoInstall, wingetDiscover, chocoDiscover = origWI, origCI, origWD, origCD
	})
}

func decodeInstall(t *testing.T, res executor.Result) InstallResult {
	t.Helper()
	var out InstallResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("stdout is not InstallResult JSON: %v (%s)", err, res.Stdout)
	}
	return out
}

func TestExecuteInstallWingetSuccess(t *testing.T) {
	var gotIDs []string
	withSeams(t, func(_ context.Context, op string, ids []string) ([]PackageOutcome, error) {
		gotIDs = ids
		outs := make([]PackageOutcome, 0, len(ids))
		for _, id := range ids {
			outs = append(outs, PackageOutcome{PackageID: id, Operation: op, ResultCode: 0})
		}
		return outs, nil
	}, nil, nil, nil)

	payload := json.RawMessage(`{"provider":"winget","operation":"install","package_ids":["Git.Git","Microsoft.PowerShell"]}`)
	res := ExecuteInstall(context.Background(), executor.KindInstallPackages, payload, Config{})
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", res.ExitCode, res.Stderr)
	}
	out := decodeInstall(t, res)
	if out.Status != "success" || len(out.Installed) != 2 || len(out.Failed) != 0 {
		t.Fatalf("unexpected result: %+v", out)
	}
	if len(gotIDs) != 2 {
		t.Fatalf("provider saw %v", gotIDs)
	}
}

func TestExecuteInstallPartialAndFailed(t *testing.T) {
	withSeams(t, func(_ context.Context, op string, ids []string) ([]PackageOutcome, error) {
		return []PackageOutcome{
			{PackageID: ids[0], Operation: op, ResultCode: 0},
			{PackageID: ids[1], Operation: op, ResultCode: 1},
		}, nil
	}, nil, nil, nil)

	res := ExecuteInstall(context.Background(), executor.KindInstallPackages,
		json.RawMessage(`{"provider":"winget","operation":"upgrade","package_ids":["A.Ok","B.Bad"]}`), Config{})
	if res.ExitCode != 0 {
		t.Fatalf("partial should not be a nonzero command exit; got %d", res.ExitCode)
	}
	out := decodeInstall(t, res)
	if out.Status != "partial" || len(out.Installed) != 1 || len(out.Failed) != 1 {
		t.Fatalf("unexpected partial result: %+v", out)
	}
}

func TestExecuteInstallRejectsUnknownFields(t *testing.T) {
	res := ExecuteInstall(context.Background(), executor.KindInstallPackages,
		json.RawMessage(`{"provider":"winget","operation":"install","package_ids":["A.B"],"extra":true}`), Config{})
	if res.ExitCode == 0 {
		t.Fatal("unknown field must be rejected")
	}
	if decodeInstall(t, res).Status != "invalid" {
		t.Fatalf("want invalid status, got %s", res.Stdout)
	}
}

func TestExecuteInstallRejectsBadProviderAndOperation(t *testing.T) {
	cases := []string{
		`{"provider":"apt","operation":"install","package_ids":["A.B"]}`,
		`{"provider":"winget","operation":"remove","package_ids":["A.B"]}`,
		`{"provider":"winget","operation":"install","package_ids":[]}`,
		`{"provider":"winget","operation":"install","package_ids":["bad id!"]}`,
	}
	for _, payload := range cases {
		res := ExecuteInstall(context.Background(), executor.KindInstallPackages, json.RawMessage(payload), Config{})
		if res.ExitCode == 0 {
			t.Fatalf("payload should have been rejected: %s", payload)
		}
	}
}

func TestExecuteInstallWingetRejectsSourceEvidence(t *testing.T) {
	res := ExecuteInstall(context.Background(), executor.KindInstallPackages,
		json.RawMessage(`{"provider":"winget","operation":"install","package_ids":["A.B"],"source":"https://x"}`), Config{})
	if res.ExitCode == 0 {
		t.Fatal("winget must not accept source evidence")
	}
}

func TestExecuteInstallChocolateyDisabledFailsClosed(t *testing.T) {
	called := false
	withSeams(t, nil, func(_ context.Context, _ string, _ []string) ([]PackageOutcome, error) {
		called = true
		return nil, nil
	}, nil, nil)

	payload := chocoInstallPayload()
	res := ExecuteInstall(context.Background(), executor.KindInstallPackages, payload, Config{ChocolateyEnabled: false})
	if res.ExitCode == 0 {
		t.Fatal("chocolatey install must fail closed when disabled")
	}
	if called {
		t.Fatal("provider must not be invoked when disabled")
	}
	if got := decodeInstall(t, res).Status; got != "refused" {
		t.Fatalf("want refused, got %s", got)
	}
}

func TestExecuteInstallChocolateyRequiresEvidence(t *testing.T) {
	withSeams(t, nil, func(_ context.Context, op string, ids []string) ([]PackageOutcome, error) {
		outs := make([]PackageOutcome, 0, len(ids))
		for _, id := range ids {
			outs = append(outs, PackageOutcome{PackageID: id, Operation: op, ResultCode: 0})
		}
		return outs, nil
	}, nil, nil)

	cfg := Config{ChocolateyEnabled: true}
	// Missing digest/signer must be refused even though chocolatey is enabled.
	bad := json.RawMessage(`{"provider":"chocolatey","operation":"install","package_ids":["googlechrome"],"source":"https://community.chocolatey.org/api/v2/"}`)
	if res := ExecuteInstall(context.Background(), executor.KindInstallPackages, bad, cfg); res.ExitCode == 0 {
		t.Fatal("chocolatey without digest/signer must be refused")
	}
	// Full evidence is accepted.
	if res := ExecuteInstall(context.Background(), executor.KindInstallPackages, chocoInstallPayload(), cfg); res.ExitCode != 0 {
		t.Fatalf("valid chocolatey install rejected: %s", res.Stderr)
	}
}

func TestExecuteInstallChocolateySourceAllowlist(t *testing.T) {
	withSeams(t, nil, func(_ context.Context, op string, ids []string) ([]PackageOutcome, error) {
		return []PackageOutcome{{PackageID: ids[0], Operation: op, ResultCode: 0}}, nil
	}, nil, nil)

	cfg := Config{ChocolateyEnabled: true, ChocolateySources: []string{"https://internal.example/nuget"}}
	if res := ExecuteInstall(context.Background(), executor.KindInstallPackages, chocoInstallPayload(), cfg); res.ExitCode == 0 {
		t.Fatal("source outside the allowlist must be refused")
	}
	cfg.ChocolateySources = []string{"https://community.chocolatey.org/api/v2/"}
	if res := ExecuteInstall(context.Background(), executor.KindInstallPackages, chocoInstallPayload(), cfg); res.ExitCode != 0 {
		t.Fatalf("allowlisted source rejected: %s", res.Stderr)
	}
}

func chocoInstallPayload() json.RawMessage {
	return json.RawMessage(`{"provider":"chocolatey","operation":"install","package_ids":["googlechrome"],` +
		`"source":"https://community.chocolatey.org/api/v2/",` +
		`"source_digest":"` + "0000000000000000000000000000000000000000000000000000000000000000" + `",` +
		`"signer":"NodeLink Ops"}`)
}

func TestScanDefaultsToWingetAndBuildsSection(t *testing.T) {
	withSeams(t, nil, nil, func(_ context.Context) ([]InstalledPackage, []UpgradablePackage, error) {
		return []InstalledPackage{{PackageID: "Git.Git", Name: "Git", Version: "2.44"}},
			[]UpgradablePackage{{PackageID: "Git.Git", CurrentVersion: "2.44", AvailableVersion: "2.45"}}, nil
	}, nil)

	result, err := Scan(context.Background(), nil, Config{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if result.Provider != ProviderWinget || len(result.Installed) != 1 || len(result.Upgradable) != 1 {
		t.Fatalf("unexpected scan result: %+v", result)
	}
	section := BuildSection(result)
	if section.Section != SectionInstalledPackages || section.Status != "ok" {
		t.Fatalf("unexpected section: %+v", section)
	}
	if _, ok := section.Payload["installed"]; !ok {
		t.Fatal("section payload missing installed list")
	}
	summary := Summarize(result)
	if summary.InstalledCount != 1 || summary.UpgradableCount != 1 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}

func TestScanChocolateyDisabledFailsClosed(t *testing.T) {
	_, err := Scan(context.Background(), json.RawMessage(`{"provider":"chocolatey"}`), Config{ChocolateyEnabled: false})
	if err == nil {
		t.Fatal("chocolatey scan must fail closed when disabled")
	}
}

func TestScanUnavailableReportsStatus(t *testing.T) {
	withSeams(t, nil, nil, func(_ context.Context) ([]InstalledPackage, []UpgradablePackage, error) {
		return nil, nil, context.DeadlineExceeded
	}, nil)
	result, err := Scan(context.Background(), nil, Config{})
	if err == nil {
		t.Fatal("expected error")
	}
	if result.Status != "unavailable" || result.ErrorCode == "" {
		t.Fatalf("unavailable scan should carry status+error: %+v", result)
	}
}

func TestNormalizePackageIDsDedupAndBound(t *testing.T) {
	ids, err := normalizePackageIDs([]string{"A.B", " A.B ", "C.D"})
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("dedup failed: %v", ids)
	}
	over := make([]string, MaxPackageTargets+1)
	for i := range over {
		over[i] = "Pkg.N"
	}
	if _, err := normalizePackageIDs(over); err == nil {
		t.Fatal("over-bound list must be rejected")
	}
}
