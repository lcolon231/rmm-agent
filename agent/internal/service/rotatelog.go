// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// rotatingWriter is an io.WriteCloser that appends to a file and rotates it once
// it would exceed maxSize bytes, keeping at most maxBackups older segments
// (named path.1 .. path.maxBackups). It lets the service log to a fixed path
// without a console while bounding disk use. It is safe for concurrent writes.
type rotatingWriter struct {
	path       string
	maxSize    int64
	maxBackups int

	mu   sync.Mutex
	f    *os.File
	size int64
}

// newRotatingWriter opens (creating if needed) the log at path, creating any
// missing parent directories.
func newRotatingWriter(path string, maxSize int64, maxBackups int) (*rotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	w := &rotatingWriter{path: path, maxSize: maxSize, maxBackups: maxBackups}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

// open attaches to the current log file in append mode, recording its size.
func (w *rotatingWriter) open() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.f = f
	w.size = info.Size()
	return nil
}

// Write appends p, rotating first if the write would breach maxSize.
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.maxSize > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxSize {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.f.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate closes the active file, shifts the backup chain (dropping the oldest),
// and opens a fresh active file.
func (w *rotatingWriter) rotate() error {
	if err := w.f.Close(); err != nil {
		return err
	}
	if w.maxBackups <= 0 {
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return w.open()
	}
	// Drop the oldest, then shift each backup up by one, then current -> .1.
	_ = os.Remove(w.backupName(w.maxBackups))
	for i := w.maxBackups - 1; i >= 1; i-- {
		_ = os.Rename(w.backupName(i), w.backupName(i+1))
	}
	if err := os.Rename(w.path, w.backupName(1)); err != nil {
		return err
	}
	return w.open()
}

func (w *rotatingWriter) backupName(i int) string {
	return fmt.Sprintf("%s.%d", w.path, i)
}

// Close closes the active log file.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}
