// SPDX-License-Identifier: AGPL-3.0-only
package pwsh

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The agent's PowerShell launches all go through this package, so the
// hardening lives in one place (issue #336). This guard fails the build when a
// package starts powershell.exe on its own again.
func TestNoPackageLaunchesPowerShellOutsidePwsh(t *testing.T) {
	found, err := findPowerShellLaunches(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if len(found) > 0 {
		t.Fatalf("PowerShell launched outside internal/pwsh; run it through pwsh.Runner (or pwsh.Args for the executor):\n%v", found)
	}
}

func TestFindPowerShellLaunchesFlagsEachShape(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/bad/direct.go", `package bad
import "os/exec"
func a() { _ = exec.Command("PowerShell.exe", "-Command", "x") }
`)
	write("internal/bad/indirect.go", `package bad
func b(run func(string, ...string)) { run("powershell.exe", "-Command", "x") }
`)
	write("internal/bad/bare.go", `package bad
import ("context"; "os/exec")
func c(ctx context.Context) { _ = exec.CommandContext(ctx, "pwsh", "-Command", "x") }
`)
	// Allowed: the module itself, command-kind names, and comments.
	write("internal/pwsh/pwsh.go", `package pwsh
const Exe = "powershell.exe"
`)
	write("internal/ok/data_test.go", `package ok
var signedFile = "powershell.exe"
`)
	write("internal/ok/ok.go", `package ok
// runs powershell.exe through pwsh
const KindPowerShell = "powershell"
`)

	found, err := findPowerShellLaunches(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/bad/bare.go:3",
		"internal/bad/direct.go:3",
		"internal/bad/indirect.go:2",
	}
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("found = %q, want %q", found, want)
	}
}
