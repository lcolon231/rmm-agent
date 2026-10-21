// SPDX-License-Identifier: AGPL-3.0-only
package chatlaunch

import (
	"errors"
	"strings"
	"testing"
)

func TestValidURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"canonical", "https://support.test/chat#c=1&t=secret", true},
		{"port kept", "https://support.test:8443/chat#x", true},
		{"ipv6 host", "https://[2001:db8::1]/chat#x", true},
		{"fragment only needs one char", "https://support.test/chat#x", true},
		{"max length", "https://support.test/chat#" + strings.Repeat("a", 4096-len("https://support.test/chat#")), true},
		{"one over max length", "https://support.test/chat#" + strings.Repeat("a", 4097-len("https://support.test/chat#")), false},
		{"empty", "", false},
		{"http", "http://support.test/chat#x", false},
		{"uppercase scheme is normalized by url.Parse", "HTTPS://support.test/chat#x", true},
		{"file scheme", "file:///C:/Windows/System32/cmd.exe", false},
		{"javascript scheme", "javascript:alert(1)", false},
		{"no scheme", "//support.test/chat#x", false},
		{"no host", "https:///chat#x", false},
		{"user only", "https://user@support.test/chat#x", false},
		{"user and password", "https://user:pw@support.test/chat#x", false},
		{"missing fragment", "https://support.test/chat", false},
		{"empty fragment", "https://support.test/chat#", false},
		{"query present", "https://support.test/chat?t=1#x", false},
		// NOTE: a bare "?" leaves RawQuery empty, so it passes the no-query rule.
		{"empty query marker", "https://support.test/chat?#x", true},
		{"wrong path", "https://support.test/other#x", false},
		{"path prefix", "https://support.test/chat/extra#x", false},
		{"trailing slash path", "https://support.test/chat/#x", false},
		{"root path", "https://support.test/#x", false},
		{"embedded space", "https://support.test/chat#a b", false},
		{"embedded quote", "https://support.test/chat#a\"b", false},
		{"embedded CR", "https://support.test/chat#a\rb", false},
		{"embedded LF", "https://support.test/chat#a\nb", false},
		{"embedded NUL", "https://support.test/chat#a\x00b", false},
		{"bad fragment escape fails to parse", "https://support.test/chat#%zz", false},
		{"bad host escape", "https://sup%zzport.test/chat#x", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validURL(tt.raw); got != tt.want {
				t.Fatalf("validURL(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestTargetOpenPassesValidatedURLVerbatim(t *testing.T) {
	const raw = "https://support.test/chat#c=conversation&t=secret"
	var got string
	target := Target{launch: func(u string) error { got = u; return nil }}
	if err := target.Open(raw); err != nil {
		t.Fatal(err)
	}
	if got != raw {
		t.Fatalf("launcher received %q, want fragment kept verbatim %q", got, raw)
	}
}

func TestTargetOpenPropagatesLaunchError(t *testing.T) {
	want := errors.New("launch failed")
	target := Target{launch: func(string) error { return want }}
	if err := target.Open("https://support.test/chat#x"); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

func TestTargetClose(t *testing.T) {
	released := 0
	target := Target{release: func() { released++ }}
	target.Close()
	if released != 1 {
		t.Fatalf("release called %d times", released)
	}
}

// Open must reject an invalid URL before any browser launch. Off Windows it is
// unsupported outright; on Windows a service-less test process has no
// WTSQueryUserToken privilege, so it also fails before launching anything.
func TestOpenNeverSucceedsForInvalidURL(t *testing.T) {
	err := Open("http://support.test/chat#x")
	if err == nil {
		t.Fatal("Open succeeded for a non-HTTPS URL")
	}
	if !errors.Is(err, ErrUnsupported) && !errors.Is(err, ErrNoSession) && !errors.Is(err, ErrURL) && !errors.Is(err, ErrLaunch) {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestForSessionRejectsInvalidSessions(t *testing.T) {
	for _, session := range []uint32{0, 0xffffffff} {
		if target, err := ForSession(session); err == nil || target != nil {
			t.Fatalf("ForSession(%#x) = %v, %v", session, target, err)
		}
	}
}
