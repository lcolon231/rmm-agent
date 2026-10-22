//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package authenticode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// These run the real Get-AuthenticodeSignature, so they prove the script and
// the parser agree with what Windows actually prints.

func TestVerifyAcceptsASignedSystemBinary(t *testing.T) {
	path := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no Windows PowerShell at %s: %v", path, err)
	}
	valid, thumb, err := Verify(context.Background(), Exec, "NL_TEST_PATH", path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid || len(thumb) != 40 {
		t.Fatalf("Verify(%s) = %v, %q; want Valid with a SHA-1 thumbprint", path, valid, thumb)
	}
}

func TestVerifyRejectsAnUnsignedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsigned.exe")
	if err := os.WriteFile(path, []byte("MZ not really a program"), 0o644); err != nil {
		t.Fatal(err)
	}
	valid, thumb, err := Verify(context.Background(), Exec, "NL_TEST_PATH", path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if valid || thumb != "" {
		t.Fatalf("Verify(unsigned) = %v, %q; want not valid and no signer", valid, thumb)
	}
}
