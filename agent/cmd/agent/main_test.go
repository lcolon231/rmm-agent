// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"os"
	"path/filepath"
	"runtime"
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
