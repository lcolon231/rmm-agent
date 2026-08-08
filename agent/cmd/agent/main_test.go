// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateServerURL(t *testing.T) {
	for _, value := range []string{"https://rmm.example.test", "http://127.0.0.1:8000", "http://[::1]:8000"} {
		if err := validateServerURL(value); err != nil {
			t.Fatalf("validateServerURL(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", "http://rmm.example.test", "https://user:pass@rmm.example.test", "https://rmm.example.test/?token=secret"} {
		if err := validateServerURL(value); err == nil {
			t.Fatalf("validateServerURL(%q) unexpectedly succeeded", value)
		}
	}
}

func TestEnrollmentTokenPrefersEnvironment(t *testing.T) {
	t.Setenv("NODELINK_TEST_TOKEN", "temporary-secret")
	got, err := enrollmentToken("NODELINK_TEST_TOKEN", "", false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "temporary-secret" {
		t.Fatalf("token = %q", got)
	}
}

func TestEnrollmentTokenReadsRestrictedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("temporary-file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := enrollmentToken("", path, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got != "temporary-file-secret" {
		t.Fatalf("token = %q", got)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := enrollmentToken("", path, false, true); err == nil {
			t.Fatal("broad token-file permissions unexpectedly accepted")
		}
	}
}

func TestNonInteractiveRequiresSecretSource(t *testing.T) {
	t.Setenv("NODELINK_MISSING_TOKEN", "")
	if _, err := enrollmentToken("NODELINK_MISSING_TOKEN", "", false, true); err == nil {
		t.Fatal("missing noninteractive token unexpectedly accepted")
	}
}

// The release build and the installer compile both assert the embedded version
// through `rmm-agent version -expect <release version>`, so an unstamped or
// mismatched binary can never be published (issue #179).
func TestVersionSubcommandPrintsAndAssertsEmbeddedVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runVersion("0.1.4", nil, &out, &errOut); code != 0 {
		t.Fatalf("version exit code = %d, stderr %q", code, errOut.String())
	}
	if strings.TrimSpace(out.String()) != "0.1.4" {
		t.Fatalf("version stdout = %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := runVersion("0.1.4", []string{"-expect", "0.1.4"}, &out, &errOut); code != 0 {
		t.Fatalf("matching -expect exit code = %d, stderr %q", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := runVersion("0.1.3", []string{"-expect", "0.1.4"}, &out, &errOut); code == 0 {
		t.Fatal("mismatched -expect unexpectedly succeeded")
	}

	out.Reset()
	errOut.Reset()
	if code := runVersion(unstampedVersion, []string{"-expect", "0.1.4"}, &out, &errOut); code == 0 {
		t.Fatal("unstamped binary unexpectedly passed -expect")
	}
	if !strings.Contains(errOut.String(), "unstamped") {
		t.Fatalf("unstamped rejection must say why; got %q", errOut.String())
	}
}

// An unstamped build still reports its fallback so a technician can tell a
// local build apart from a release artifact.
func TestVersionSubcommandReportsUnstampedBuildsWithoutExpect(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := runVersion(unstampedVersion, nil, &out, &errOut); code != 0 {
		t.Fatalf("version exit code = %d", code)
	}
	if strings.TrimSpace(out.String()) != unstampedVersion {
		t.Fatalf("version stdout = %q", out.String())
	}
}
