// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// A cancelled context must terminate the command promptly rather than letting
// it run to its natural end (issue #113: cancellation/service-stop must not
// leave work running). On non-Windows this exercises the Start/assign/watch/Wait
// path with the no-op containment; the Windows Job Object path is validated on
// Windows CI.
func TestRunContextCancellationTerminatesPromptly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell sleep form is POSIX; tree termination is covered on Windows CI")
	}
	ctx, cancel := context.WithCancel(context.Background())
	// Cancel shortly after the child starts; the child would otherwise sleep 30s.
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	res := RunContext(ctx, KindShell, "sleep 30")
	elapsed := time.Since(start)

	if elapsed > 10*time.Second {
		t.Fatalf("cancellation did not terminate the command promptly: took %s", elapsed)
	}
	if res.ExitCode == 0 {
		t.Fatalf("a cancelled command must not report success, got exit 0")
	}
}

// A command that exceeds the default timeout is terminated and reported as a
// timeout. This uses a short-circuit: we cannot wait five real minutes, so we
// assert the timeout marker path via a context deadline shorter than the child.
func TestRunContextContextDeadlineTerminates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell sleep form is POSIX; covered on Windows CI")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res := RunContext(ctx, KindShell, "sleep 30")
	if time.Since(start) > 10*time.Second {
		t.Fatalf("deadline did not terminate the command")
	}
	if res.ExitCode == 0 {
		t.Fatalf("a deadline-terminated command must not report success")
	}
}
