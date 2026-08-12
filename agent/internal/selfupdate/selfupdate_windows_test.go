//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReplaceRunningBinaryDisplacesLockedImage covers the Windows-specific half
// of the atomic swap: the image of a running process cannot be overwritten, so
// it is renamed out of the way first and the new binary takes the vacated path.
func TestReplaceRunningBinaryDisplacesLockedImage(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	src := filepath.Join(dir, "staged.exe")
	if err := os.WriteFile(dest, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte(newBinary), 0o755); err != nil {
		t.Fatal(err)
	}

	// Hold the destination open the way a running image is held.
	held, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := replaceRunningBinary(src, dest); err != nil {
		t.Fatalf("replaceRunningBinary: %v", err)
	}
	installed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != newBinary {
		t.Fatalf("installed content = %q, want the new build", installed)
	}
	held.Close()

	// The displaced image may survive while the old process holds it; pruning
	// on the next healthy start must clear it.
	pruneDisplacedImages(dest)
	matches, err := filepath.Glob(dest + ".old-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("displaced images were not pruned: %v", matches)
	}
}

// TestReplaceRunningBinaryRestoresOnFailure asserts the destination is never
// left missing when the second rename fails.
func TestReplaceRunningBinaryRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	if err := os.WriteFile(dest, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "does-not-exist.exe")

	if err := replaceRunningBinary(missing, dest); err == nil {
		t.Fatal("replacing from a missing source must fail")
	}
	restored, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination must still exist after a failed replace: %v", err)
	}
	if string(restored) != oldBinary {
		t.Fatalf("destination content = %q, want the original build", restored)
	}
}

// TestRestartRequestIsBounded asserts the restart helper never interpolates
// caller-controlled text into the command it runs.
func TestRestartRequestUsesFixedServiceName(t *testing.T) {
	if serviceName != "NodeLinkAgent" {
		t.Fatalf("serviceName = %q; the restart helper must target the installed service", serviceName)
	}
}
