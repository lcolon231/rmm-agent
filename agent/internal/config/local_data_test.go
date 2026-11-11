// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testLocalFormat  = "nodelink-test-local-state"
	testLocalVersion = 3
)

// withPlatformProtector swaps the package-level protector for the duration of
// a test. Tests in this package do not run in parallel, so the swap is safe.
func withPlatformProtector(t *testing.T, p protector) {
	t.Helper()
	prev := platformProtector
	platformProtector = p
	t.Cleanup(func() { platformProtector = prev })
}

// failingProtector refuses every operation, standing in for a DPAPI failure
// (wrong account, corrupt key material, service profile not loaded).
type failingProtector struct{ scheme string }

var errProtectorRefused = errors.New("protector refused")

func (f failingProtector) Scheme() string                 { return f.scheme }
func (failingProtector) Protect([]byte) ([]byte, error)   { return nil, errProtectorRefused }
func (failingProtector) Unprotect([]byte) ([]byte, error) { return nil, errProtectorRefused }

func protectedEnvelope(t *testing.T, plain []byte) ProtectedLocalData {
	t.Helper()
	raw, err := ProtectLocalData(testLocalFormat, testLocalVersion, plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	var env ProtectedLocalData
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("protected output is not an envelope: %v: %s", err, raw)
	}
	return env
}

// TestLocalDataRoundTripPlatformProtector uses the real platform protector:
// DPAPI on the Windows job, the explicit "none" scheme elsewhere.
func TestLocalDataRoundTripPlatformProtector(t *testing.T) {
	plain := []byte(`{"cmd-1":{"result":"buffered-secret-output"}}`)
	raw, err := ProtectLocalData(testLocalFormat, testLocalVersion, plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	var env ProtectedLocalData
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("protected output is not an envelope: %v", err)
	}
	if env.Format != testLocalFormat || env.Version != testLocalVersion {
		t.Fatalf("envelope header = %q v%d", env.Format, env.Version)
	}
	if env.Protection != platformProtector.Scheme() {
		t.Fatalf("envelope protection %q != platform %q", env.Protection, platformProtector.Scheme())
	}

	got, legacy, err := UnprotectLocalData(raw, testLocalFormat, testLocalVersion)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if legacy {
		t.Fatal("freshly protected envelope reported as legacy")
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: %q", got)
	}
}

// TestLocalDataRoundTripEncrypts uses a non-identity protector so the
// "ciphertext never contains the plaintext" property is checked on every
// platform, not only on the Windows job.
func TestLocalDataRoundTripEncrypts(t *testing.T) {
	withPlatformProtector(t, xorProtector{})
	plain := []byte("buffered-secret-output")
	raw, err := ProtectLocalData(testLocalFormat, testLocalVersion, plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if bytes.Contains(raw, plain) {
		t.Fatalf("protected envelope contains plaintext: %s", raw)
	}
	got, legacy, err := UnprotectLocalData(raw, testLocalFormat, testLocalVersion)
	if err != nil || legacy || !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q legacy=%v err=%v", got, legacy, err)
	}
}

func TestProtectLocalDataRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		format  string
		version int
		plain   []byte
		want    string
	}{
		{"empty format", "", 1, []byte("x"), "format and positive version"},
		{"zero version", testLocalFormat, 0, []byte("x"), "format and positive version"},
		{"negative version", testLocalFormat, -1, []byte("x"), "format and positive version"},
		{"nil payload", testLocalFormat, 1, nil, "empty local-state payload"},
		{"empty payload", testLocalFormat, 1, []byte{}, "empty local-state payload"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ProtectLocalData(tc.format, tc.version, tc.plain)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if out != nil {
				t.Fatalf("output returned alongside error: %q", out)
			}
		})
	}
}

// TestProtectLocalDataFailsClosed: when the protector fails nothing is
// returned — there is no plaintext fallback.
func TestProtectLocalDataFailsClosed(t *testing.T) {
	withPlatformProtector(t, failingProtector{scheme: "dpapi"})
	out, err := ProtectLocalData(testLocalFormat, testLocalVersion, []byte("secret"))
	if !errors.Is(err, errProtectorRefused) {
		t.Fatalf("err = %v, want wrapped protector error", err)
	}
	if !strings.Contains(err.Error(), "dpapi") {
		t.Fatalf("error does not name the scheme: %v", err)
	}
	if out != nil {
		t.Fatalf("output returned despite protect failure: %q", out)
	}
}

func TestUnprotectLocalDataRejectsMismatchedEnvelope(t *testing.T) {
	withPlatformProtector(t, xorProtector{})
	good := protectedEnvelope(t, []byte("payload"))

	for _, tc := range []struct {
		name    string
		mutate  func(*ProtectedLocalData)
		format  string
		version int
		want    string
	}{
		{"other format", func(*ProtectedLocalData) {}, "nodelink-other-state", testLocalVersion, "is not"},
		{"older version", func(*ProtectedLocalData) {}, testLocalFormat, testLocalVersion + 1, "version 3 is not supported"},
		{"newer version", func(e *ProtectedLocalData) { e.Version = 99 }, testLocalFormat, testLocalVersion, "version 99"},
		// An envelope claiming another protection scheme (e.g. "none" on a
		// DPAPI platform) must never be passed to this platform's unprotector
		// or read as plaintext.
		{"plaintext scheme claimed", func(e *ProtectedLocalData) { e.Protection = "none" }, testLocalFormat, testLocalVersion, "this platform requires"},
		{"dpapi scheme claimed", func(e *ProtectedLocalData) { e.Protection = "dpapi" }, testLocalFormat, testLocalVersion, "this platform requires"},
		{"empty scheme", func(e *ProtectedLocalData) { e.Protection = "" }, testLocalFormat, testLocalVersion, "this platform requires"},
		{"invalid base64", func(e *ProtectedLocalData) { e.Data = "!!not-base64!!" }, testLocalFormat, testLocalVersion, "corrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := good
			tc.mutate(&env)
			raw, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			plain, legacy, err := UnprotectLocalData(raw, tc.format, tc.version)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if plain != nil || legacy {
				t.Fatalf("fail-closed path returned plain=%q legacy=%v", plain, legacy)
			}
		})
	}
}

// TestUnprotectLocalDataSurfacesProtectorFailure covers tampered ciphertext,
// a blob written by another account, or any other unprotect failure.
func TestUnprotectLocalDataSurfacesProtectorFailure(t *testing.T) {
	withPlatformProtector(t, failingProtector{scheme: "test-fail"})
	raw, err := json.Marshal(ProtectedLocalData{
		Format:     testLocalFormat,
		Version:    testLocalVersion,
		Protection: "test-fail",
		Data:       base64.StdEncoding.EncodeToString([]byte("opaque")),
	})
	if err != nil {
		t.Fatal(err)
	}
	plain, legacy, err := UnprotectLocalData(raw, testLocalFormat, testLocalVersion)
	if !errors.Is(err, errProtectorRefused) {
		t.Fatalf("err = %v, want wrapped protector error", err)
	}
	if plain != nil || legacy {
		t.Fatalf("failure returned plain=%q legacy=%v", plain, legacy)
	}
}

// TestUnprotectLocalDataLegacyPassThrough pins the documented migration
// contract: input that is not an envelope is handed back verbatim with
// legacy=true. That includes a truncated envelope — it is not decrypted or
// "repaired"; the caller's own parse of the legacy format rejects it.
func TestUnprotectLocalDataLegacyPassThrough(t *testing.T) {
	withPlatformProtector(t, xorProtector{})
	full, err := ProtectLocalData(testLocalFormat, testLocalVersion, []byte(`{"k":1}`))
	if err != nil {
		t.Fatal(err)
	}
	truncated := full[:len(full)/2]

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"legacy JSON map", []byte(`{"cmd-1":{"expiry":"2026-01-01T00:00:00Z"}}`)},
		{"not JSON", []byte("plain text")},
		{"truncated envelope", truncated},
		{"envelope without format", []byte(`{"version":3,"protection":"test-xor","data":""}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plain, legacy, err := UnprotectLocalData(tc.data, testLocalFormat, testLocalVersion)
			if err != nil {
				t.Fatalf("legacy input errored: %v", err)
			}
			if !legacy {
				t.Fatal("non-envelope input not reported as legacy")
			}
			if !bytes.Equal(plain, tc.data) {
				t.Fatalf("legacy input altered: %q", plain)
			}
		})
	}

	var m map[string]json.RawMessage
	if json.Unmarshal(truncated, &m) == nil {
		t.Fatal("truncated envelope parsed as valid legacy JSON")
	}
}

// TestApplyLocalDataACL: off Windows the ACL is the 0600 mode and applying
// it is a no-op; the Windows job asserts the real DACL separately.
func TestApplyLocalDataACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLocalDataACL(path); err != nil {
		t.Fatalf("apply ACL: %v", err)
	}
}

func TestSaveIdentityFailsClosedWhenProtectFails(t *testing.T) {
	withPlatformProtector(t, failingProtector{scheme: "dpapi"})
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := sampleIdentity().Save(path); !errors.Is(err, errProtectorRefused) {
		t.Fatalf("err = %v, want wrapped protector error", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("identity written despite protect failure: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file written despite protect failure: %v", err)
	}
}

func TestSaveIdentityWriteErrors(t *testing.T) {
	dir := t.TempDir()
	// Parent directory does not exist: the temp write fails.
	if err := sampleIdentity().Save(filepath.Join(dir, "missing", "identity.json")); err == nil {
		t.Fatal("save into missing directory succeeded")
	}
	// Destination is a non-empty directory: the rename fails and the temp
	// file is cleaned up.
	target := filepath.Join(dir, "identity.json")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := sampleIdentity().Save(target); err == nil {
		t.Fatal("save over a directory succeeded")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind after failed rename: %v", err)
	}
}

func TestSaveConfigWriteErrors(t *testing.T) {
	dir := t.TempDir()
	if err := SaveInstallConfig(filepath.Join(dir, "missing", "config.json"), "https://rmm.example"); err == nil {
		t.Fatal("save into missing directory succeeded")
	}
	target := filepath.Join(dir, "config.json")
	if err := os.MkdirAll(filepath.Join(target, "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveInstallConfig(target, "https://rmm.example"); err == nil {
		t.Fatal("save over a directory succeeded")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind after failed rename: %v", err)
	}
}

func TestLoadIdentityCorruptEnvelopeIsError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte(`{"format":"nodelink-agent-identity","version":1,"protection":"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path); err == nil {
		t.Fatal("truncated identity envelope loaded")
	}
}
