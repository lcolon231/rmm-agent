// SPDX-License-Identifier: AGPL-3.0-only

package executor

import "unicode/utf8"

// Output capture limits. Each stream is captured up to its own cap, and the
// pair together may not exceed the combined cap. When the combined cap is
// exceeded, stderr is preserved (diagnostics matter most) and stdout is
// trimmed to the remaining budget — a deterministic rule independent of how
// the child interleaved its writes. Bytes beyond a cap are counted but never
// buffered, so a runaway command cannot exhaust agent memory.
const (
	// MaxStreamBytes bounds stdout and stderr independently.
	MaxStreamBytes = 256 * 1024
	// MaxCombinedBytes bounds stdout + stderr together.
	MaxCombinedBytes = 384 * 1024
)

// limitWriter keeps at most max bytes in memory while counting everything
// written. Excess bytes are discarded on arrival, not buffered.
type limitWriter struct {
	max   int
	buf   []byte
	total int64
}

func (w *limitWriter) Write(p []byte) (int, error) {
	n := len(p)
	w.total += int64(n)
	if remaining := w.max - len(w.buf); remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		w.buf = append(w.buf, p...)
	}
	// Always report the full original length: a short-write here would make
	// io.Copy abort and close the pipe, killing the child with SIGPIPE.
	return n, nil
}

// truncated reports whether any bytes were discarded.
func (w *limitWriter) truncated() bool { return w.total > int64(len(w.buf)) }

// trimIncompleteRune backs off a byte-boundary truncation so the result never
// ends in a split multibyte UTF-8 sequence. At most 3 bytes are dropped.
func trimIncompleteRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax-1 && len(b) > 0; i++ {
		r, size := utf8.DecodeLastRune(b)
		if r != utf8.RuneError || size != 1 {
			return b
		}
		// A trailing RuneError of size 1 is an incomplete/invalid final byte;
		// only strip it when it is plausibly the start of a cut-off sequence.
		last := b[len(b)-1]
		if last < 0x80 {
			return b // plain ASCII, not a split rune
		}
		b = b[:len(b)-1]
		if last >= 0xC0 {
			return b // that byte started the rune; sequence is now whole again
		}
	}
	return b
}

// applyOutputLimits enforces the combined cap over two already stream-capped
// buffers and returns the final strings plus truncation flags. Totals are the
// original byte counts the child actually produced.
func applyOutputLimits(stdout, stderr *limitWriter) (outStr, errStr string, outTrunc, errTrunc bool) {
	outBytes, errBytes := stdout.buf, stderr.buf
	if len(outBytes)+len(errBytes) > MaxCombinedBytes {
		keep := MaxCombinedBytes - len(errBytes)
		if keep < 0 {
			keep = 0
		}
		outBytes = outBytes[:keep]
	}
	outBytes = trimIncompleteRune(outBytes)
	errBytes = trimIncompleteRune(errBytes)
	// A stream is truncated iff fewer bytes survive than the child produced,
	// whichever cap (stream, combined, or rune-boundary trim) removed them.
	outTrunc = stdout.total > int64(len(outBytes))
	errTrunc = stderr.total > int64(len(errBytes))
	return string(outBytes), string(errBytes), outTrunc, errTrunc
}
