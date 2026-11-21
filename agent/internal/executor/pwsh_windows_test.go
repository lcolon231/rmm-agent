//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// Operator scripts keep the executor's own Job Object lifecycle, but start
// PowerShell with the one hardened flag set pwsh defines.
func TestPowerShellCommandsUseTheSharedFlagSet(t *testing.T) {
	for _, kind := range []string{KindPowerShell, KindInventory} {
		cmd := buildCommand(kind, "Get-Date")
		if !strings.EqualFold(filepath.Base(cmd.Path), pwsh.Exe) {
			t.Fatalf("%s runs %q", kind, cmd.Path)
		}
		if want := pwsh.Args(pwsh.Script{Body: "Get-Date"}); !reflect.DeepEqual(cmd.Args[1:], want) {
			t.Fatalf("%s args = %q, want %q", kind, cmd.Args[1:], want)
		}
	}
	interactive := interactiveCommand()
	if want := pwsh.StdinArgs(); !reflect.DeepEqual(interactive.Args[1:], want) {
		t.Fatalf("interactive args = %q, want %q", interactive.Args[1:], want)
	}
}
