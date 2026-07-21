//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestDPAPIRoundTrip exercises the real DPAPI protector under the CI account.
func TestDPAPIRoundTrip(t *testing.T) {
	p := dpapiProtector{}
	plain := []byte(`{"agent_token":"windows-secret"}`)

	blob, err := p.Protect(plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if bytes.Contains(blob, []byte("windows-secret")) {
		t.Fatalf("DPAPI blob contains plaintext")
	}
	out, err := p.Unprotect(blob)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("round trip mismatch")
	}
}

func TestDPAPIUnprotectRejectsCorruptBlob(t *testing.T) {
	p := dpapiProtector{}
	if _, err := p.Unprotect([]byte("definitely not a DPAPI blob")); err == nil {
		t.Fatalf("expected corrupt blob to fail")
	}
	if _, err := p.Unprotect(nil); err == nil {
		t.Fatalf("expected empty blob to fail")
	}
}

// TestIdentityACLApplied verifies the saved identity's DACL is the restricted
// one (SYSTEM + Administrators only, inheritance blocked).
func TestIdentityACLApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := sampleIdentity().Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}

	// icacls prints one line per ACE; the restricted DACL must reference only
	// SYSTEM and Administrators and must not carry inherited entries (which
	// icacls marks with (I)). Match fully qualified principal names followed by
	// ":" so the file path itself (e.g. C:\Users\...) cannot false-positive.
	out, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatalf("icacls: %v: %s", err, out)
	}
	text := string(out)
	if strings.Contains(text, "(I)") {
		t.Fatalf("identity file has inherited ACEs:\n%s", text)
	}
	for _, banned := range []string{`BUILTIN\Users:`, "Everyone:", `NT AUTHORITY\Authenticated Users:`} {
		if strings.Contains(text, banned) {
			t.Fatalf("identity file grants access to %q:\n%s", banned, text)
		}
	}
}
