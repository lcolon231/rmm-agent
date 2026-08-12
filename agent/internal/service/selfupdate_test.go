// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/executor"
	"github.com/lcolon231/rmm/agent/internal/selfupdate"
)

func TestSelfUpdateOptionsDescribeThisEndpoint(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "rmm-agent")
	if err := os.WriteFile(exe, []byte("BINARY"), 0o755); err != nil {
		t.Fatal(err)
	}
	original := executablePath
	executablePath = func() (string, error) { return exe, nil }
	t.Cleanup(func() { executablePath = original })

	agent := NewAgent("config.json", "0.1.5", log.New(os.Stderr, "", 0))
	opts, err := agent.selfUpdateOptions(&session{updateChannel: "beta"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.CurrentVersion != "0.1.5" || opts.ExePath != exe || opts.Channel != "beta" {
		t.Fatalf("unexpected options: %+v", opts)
	}
	if want := runtime.GOOS + "/" + runtime.GOARCH; opts.Platform != want {
		t.Fatalf("platform = %q, want %q", opts.Platform, want)
	}
	// The update root lives next to the executable so the staged binary and the
	// binary it replaces are on the same volume; that is what makes the swap a
	// rename rather than a copy.
	if opts.Root != "" && !strings.HasPrefix(opts.Root, filepath.Dir(exe)) {
		t.Fatalf("update root %q must sit beside the executable", opts.Root)
	}
}

// TestRunSelfUpdateFailsClosedWithoutAnExecutablePath asserts the runner reports
// structured evidence instead of panicking or silently doing nothing when the
// endpoint's own binary cannot be located.
func TestRunSelfUpdateFailsClosedWithoutAnExecutablePath(t *testing.T) {
	original := executablePath
	executablePath = func() (string, error) { return "", fmt.Errorf("no executable") }
	t.Cleanup(func() { executablePath = original })

	agent := NewAgent("config.json", "0.1.5", log.New(os.Stderr, "", 0))
	res := agent.runSelfUpdate(
		context.Background(), &session{}, "cmd-1", executor.KindAgentSelfUpdate, json.RawMessage(`{}`),
	)
	if res.ExitCode == 0 {
		t.Fatal("a self-update with no resolvable executable must fail")
	}
	var evidence selfupdate.Result
	if err := json.Unmarshal([]byte(res.Stdout), &evidence); err != nil {
		t.Fatalf("expected JSON evidence, got %q", res.Stdout)
	}
	if evidence.Status != selfupdate.StatusInvalid {
		t.Fatalf("status = %q, want %q", evidence.Status, selfupdate.StatusInvalid)
	}
}
