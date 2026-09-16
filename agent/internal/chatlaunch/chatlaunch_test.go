// SPDX-License-Identifier: AGPL-3.0-only
package chatlaunch

import (
	"runtime"
	"strings"
	"testing"
)

func TestOnlyHTTPSChatURLsReachLauncher(t *testing.T) {
	for _, raw := range []string{"file:///C:/Windows/System32/cmd.exe", "https://user:secret@host/chat#x", "http://host/chat#x", "https://host/other#x", "https://host/chat?t=secret", "https://host/chat#x\" extra", strings.Repeat("x", 4097)} {
		called := false
		target := Target{launch: func(string) error { called = true; return nil }}
		if target.Open(raw) != ErrURL || called {
			t.Fatalf("unsafe input reached launcher")
		}
	}
	target := Target{launch: func(raw string) error { return nil }}
	if err := target.Open("https://support.test/chat#c=conversation&t=secret"); err != nil {
		t.Fatal(err)
	}
}
func TestNonWindowsUnsupported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows contract")
	}
	if Open("https://support.test/chat#x") != ErrUnsupported {
		t.Fatal("expected unsupported")
	}
}
