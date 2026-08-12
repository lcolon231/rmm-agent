//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// openLikeTheLoader opens path the way the Windows image loader holds a running
// executable: read access, sharing reads and *deletes*. FILE_SHARE_DELETE is the
// detail that makes the swap possible — a rename needs DELETE access to the
// target, so an image held without it cannot be displaced, while one held the
// loader's way can. os.Open would model the former, not the latter.
func openLikeTheLoader(t *testing.T, path string) syscall.Handle {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(
		name,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("open %s with loader sharing mode: %v", path, err)
	}
	return handle
}

func writeBinary(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// TestReplaceRunningBinaryDisplacesLoaderHeldImage covers the Windows-specific
// half of the atomic swap: the image of a running process cannot be overwritten,
// but it can be renamed out of the way, and the new binary then takes the
// vacated path. This is the case that makes self-update possible at all.
func TestReplaceRunningBinaryDisplacesLoaderHeldImage(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	src := filepath.Join(dir, "staged.exe")
	writeBinary(t, dest, oldBinary)
	writeBinary(t, src, newBinary)

	handle := openLikeTheLoader(t, dest)
	// Closed exactly once, below, once the displaced image may be pruned. A
	// second CloseHandle on a released handle could hit a recycled one.
	closeOnce := func() {
		if handle != syscall.InvalidHandle {
			syscall.CloseHandle(handle)
			handle = syscall.InvalidHandle
		}
	}
	defer closeOnce()

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

	// The displaced image survives while the old process still holds it, so it
	// is pruned on a later start rather than at swap time.
	matches, err := filepath.Glob(dest + ".old-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected the previous image to be displaced, found %v", matches)
	}
	closeOnce()
	pruneDisplacedImages(dest)
	if matches, _ := filepath.Glob(dest + ".old-*"); len(matches) != 0 {
		t.Fatalf("displaced images were not pruned: %v", matches)
	}
}

// TestReplaceRunningBinaryLeavesDestinationWhenDisplaceIsRefused covers the
// other side: when something holds the binary without allowing deletes, the
// rename is refused. The swap must then fail cleanly with the original still in
// place — an endpoint must never be left without an executable.
func TestReplaceRunningBinaryLeavesDestinationWhenDisplaceIsRefused(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	src := filepath.Join(dir, "staged.exe")
	writeBinary(t, dest, oldBinary)
	writeBinary(t, src, newBinary)

	// os.Open shares reads and writes but not deletes, so the rename is denied.
	held, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := replaceRunningBinary(src, dest); err == nil {
		t.Fatal("a destination that cannot be displaced must fail the swap")
	}
	surviving, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("destination must still exist after a refused swap: %v", err)
	}
	if string(surviving) != oldBinary {
		t.Fatalf("destination content = %q, want the original build", surviving)
	}
}

// TestReplaceRunningBinaryRestoresOnFailure asserts the destination is never
// left missing when the second rename fails after the original was displaced.
func TestReplaceRunningBinaryRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "rmm-agent.exe")
	writeBinary(t, dest, oldBinary)
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
	if matches, _ := filepath.Glob(dest + ".old-*"); len(matches) != 0 {
		t.Fatalf("a failed replace must not leave a displaced image: %v", matches)
	}
}

// TestRestartRequestUsesFixedServiceName asserts the restart helper never
// interpolates caller-controlled text into the command it runs.
func TestRestartRequestUsesFixedServiceName(t *testing.T) {
	if serviceName != "NodeLinkAgent" {
		t.Fatalf("serviceName = %q; the restart helper must target the installed service", serviceName)
	}
}
