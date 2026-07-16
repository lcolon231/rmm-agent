package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingWriterRotatesAndCapsBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	// maxSize 50 bytes, keep 2 backups.
	w, err := newRotatingWriter(path, 50, 2)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	line := strings.Repeat("x", 20) + "\n" // 21 bytes per write
	for i := 0; i < 20; i++ {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	// Active log plus at most maxBackups backups may exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active log missing: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected backup .1 to exist: %v", err)
	}
	if _, err := os.Stat(path + ".2"); err != nil {
		t.Fatalf("expected backup .2 to exist: %v", err)
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatalf("backup .3 should not exist (retention exceeded)")
	}
}

func TestRotatingWriterKeepsBytesBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	w, err := newRotatingWriter(path, 100, 1)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < 100; i++ {
		if _, err := fmt.Fprintf(w, "line %d padded padded padded\n", i); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// Total on-disk bytes are bounded by (maxBackups+1) * maxSize, roughly.
	var total int64
	for _, p := range []string{path, path + ".1", path + ".2"} {
		if info, err := os.Stat(p); err == nil {
			total += info.Size()
		}
	}
	if total > (1+1)*100+200 { // small slack for a final partial write
		t.Fatalf("on-disk log grew unbounded: %d bytes", total)
	}
}

func TestRotatingWriterAppendsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	w, err := newRotatingWriter(path, 1<<20, 3)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	if _, err := w.Write([]byte("first\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close()

	// Reopening the same path should not truncate existing content.
	w2, err := newRotatingWriter(path, 1<<20, 3)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer w2.Close()
	if _, err := w2.Write([]byte("second\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), "first") || !strings.Contains(string(data), "second") {
		t.Fatalf("expected appended content, got %q", string(data))
	}
}
