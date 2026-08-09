//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package remediation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRejectReparsePoint(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating a Windows symlink requires privilege: %v", err)
	}
	if err := rejectReparse(filepath.Join(link, "payload.bin")); err == nil {
		t.Fatal("path through a reparse point was accepted")
	}
}
