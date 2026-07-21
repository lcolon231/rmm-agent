// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"unicode/utf8"
)

func writeAll(w *limitWriter, s string, chunk int) {
	b := []byte(s)
	for len(b) > 0 {
		n := chunk
		if n > len(b) {
			n = len(b)
		}
		_, _ = w.Write(b[:n])
		b = b[n:]
	}
}

func TestLimitWriterExactBoundaryIsNotTruncated(t *testing.T) {
	w := &limitWriter{max: 8}
	writeAll(w, "12345678", 3)
	if w.truncated() {
		t.Fatalf("exact-cap write reported truncated")
	}
	if got := string(w.buf); got != "12345678" {
		t.Fatalf("buf = %q", got)
	}
}

func TestLimitWriterOverLimitCountsButDoesNotBuffer(t *testing.T) {
	w := &limitWriter{max: 4}
	writeAll(w, "123456789", 2)
	if !w.truncated() {
		t.Fatalf("over-cap write not reported truncated")
	}
	if got := string(w.buf); got != "1234" {
		t.Fatalf("buf = %q, want first 4 bytes", got)
	}
	if w.total != 9 {
		t.Fatalf("total = %d, want 9", w.total)
	}
}

func TestTrimIncompleteRune(t *testing.T) {
	// "héllo" cut mid-'é' (0xC3 0xA9) must lose the dangling lead byte.
	full := []byte("h\xc3\xa9")
	cut := full[:2] // "h" + first byte of é
	got := trimIncompleteRune(cut)
	if string(got) != "h" {
		t.Fatalf("trim = %q, want %q", got, "h")
	}
	// A complete multibyte tail is preserved untouched.
	if got := trimIncompleteRune(full); string(got) != "h\xc3\xa9" {
		t.Fatalf("complete rune was trimmed: %q", got)
	}
	// 4-byte emoji cut after 2 bytes loses both dangling bytes.
	emoji := []byte("a\xf0\x9f\x98\x80") // "a😀"
	got = trimIncompleteRune(emoji[:3])
	if string(got) != "a" {
		t.Fatalf("emoji trim = %q, want %q", got, "a")
	}
}

func TestApplyOutputLimitsCombinedCapPreservesStderr(t *testing.T) {
	// Both streams at their individual caps: combined cap forces stdout to
	// shrink to (combined - stderr), stderr stays whole.
	stdout := &limitWriter{max: MaxStreamBytes}
	stderr := &limitWriter{max: MaxStreamBytes}
	writeAll(stdout, strings.Repeat("o", MaxStreamBytes+10), 8192)
	writeAll(stderr, strings.Repeat("e", MaxStreamBytes), 8192)

	outStr, errStr, outTrunc, errTrunc := applyOutputLimits(stdout, stderr)
	if len(errStr) != MaxStreamBytes {
		t.Fatalf("stderr len = %d, want full %d", len(errStr), MaxStreamBytes)
	}
	if want := MaxCombinedBytes - MaxStreamBytes; len(outStr) != want {
		t.Fatalf("stdout len = %d, want %d", len(outStr), want)
	}
	if !outTrunc {
		t.Fatalf("stdout not flagged truncated")
	}
	if errTrunc {
		t.Fatalf("stderr wrongly flagged truncated")
	}
}

func TestApplyOutputLimitsUnderCapsIsUntouched(t *testing.T) {
	stdout := &limitWriter{max: MaxStreamBytes}
	stderr := &limitWriter{max: MaxStreamBytes}
	writeAll(stdout, "hello", 2)
	writeAll(stderr, "wörld", 2)
	outStr, errStr, outTrunc, errTrunc := applyOutputLimits(stdout, stderr)
	if outStr != "hello" || errStr != "wörld" || outTrunc || errTrunc {
		t.Fatalf("under-cap output altered: %q %q %v %v", outStr, errStr, outTrunc, errTrunc)
	}
}

func TestApplyOutputLimitsMultibyteBoundaryStaysValidUTF8(t *testing.T) {
	// Fill stdout with 3-byte runes so the cap lands mid-rune.
	stdout := &limitWriter{max: MaxStreamBytes}
	stderr := &limitWriter{max: MaxStreamBytes}
	writeAll(stdout, strings.Repeat("€", MaxStreamBytes/3+10), 4096)
	outStr, _, outTrunc, _ := applyOutputLimits(stdout, stderr)
	if !utf8.ValidString(outStr) {
		t.Fatalf("truncated stdout is not valid UTF-8")
	}
	if !outTrunc {
		t.Fatalf("stdout not flagged truncated")
	}
	if len(outStr) > MaxStreamBytes {
		t.Fatalf("stdout exceeds stream cap: %d", len(outStr))
	}
}

// TestRunContextTruncatesRealProcess drives a real child that floods stdout
// and confirms bounded capture with intact exit status and totals.
func TestRunContextTruncatesRealProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell kind is not built on windows in this test's form")
	}
	// ~556 KiB of stdout, well past the 256 KiB stream cap. Generated with a
	// printf loop rather than a pipeline so no stage can die of SIGPIPE.
	const chunks = (MaxStreamBytes + 300*1024) / 1024
	script := fmt.Sprintf(
		`b='%s'; c=0; while [ $c -lt %d ]; do printf %%s "$b"; c=$((c+1)); done`,
		strings.Repeat("x", 1024), chunks,
	)
	res := RunContext(context.Background(), KindShell, script)
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, stderr = %q", res.ExitCode, res.Stderr)
	}
	if !res.StdoutTruncated {
		t.Fatalf("stdout not flagged truncated")
	}
	if len(res.Stdout) != MaxStreamBytes {
		t.Fatalf("stdout kept %d bytes, want %d", len(res.Stdout), MaxStreamBytes)
	}
	if want := int64(chunks * 1024); res.StdoutTotalBytes != want {
		t.Fatalf("stdout total = %d, want %d", res.StdoutTotalBytes, want)
	}
	if res.StderrTruncated || res.StderrTotalBytes != 0 {
		t.Fatalf("stderr unexpectedly flagged: %+v", res)
	}
}
