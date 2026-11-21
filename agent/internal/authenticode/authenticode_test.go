// SPDX-License-Identifier: AGPL-3.0-only
package authenticode

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

func TestScriptKeepsThePathOutOfTheBody(t *testing.T) {
	path := `C:\tmp\a b;$(evil).exe`
	s := Script("NL_TEST_PATH", path)
	if !strings.Contains(s.Body, "Get-AuthenticodeSignature -LiteralPath $env:NL_TEST_PATH;") {
		t.Fatalf("script does not read the path from the environment: %q", s.Body)
	}
	if strings.Contains(s.Body, "evil") {
		t.Fatalf("path leaked into the script: %q", s.Body)
	}
	if !reflect.DeepEqual(s.Env, map[string]string{"NL_TEST_PATH": path}) || s.Timeout != Timeout {
		t.Fatalf("script = %+v", s)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		out       string
		wantValid bool
		wantThumb string
	}{
		{"valid with signer", "Valid|AABBCC\r\n", true, "AABBCC"},
		{"status is case-insensitive", "valid|AABBCC", true, "AABBCC"},
		{"surrounding whitespace", "  Valid | AABBCC  \n", true, "AABBCC"},
		{"unsigned has no signer", "NotSigned|\r\n", false, ""},
		{"tampered still names a signer", "HashMismatch|AABBCC", false, "AABBCC"},
		{"untrusted root", "UnknownError|AABBCC", false, "AABBCC"},
		{"status alone", "Valid", true, ""},
		{"empty output", "", false, ""},
		{"a prefix of Valid is not Valid", "Valid-ish|AABBCC", false, "AABBCC"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, thumb := Parse([]byte(tt.out))
			if valid != tt.wantValid || thumb != tt.wantThumb {
				t.Fatalf("Parse(%q) = %v, %q; want %v, %q", tt.out, valid, thumb, tt.wantValid, tt.wantThumb)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	const thumb = "0123456789ABCDEF0123456789ABCDEF01234567"
	tests := []struct {
		name       string
		reply      func(pwsh.Script) (pwsh.Result, error)
		wantValid  bool
		wantThumb  string
		wantErrHas []string
	}{
		{"signed", pwshtest.Stdout("Valid|" + thumb + "\r\n"), true, thumb, nil},
		// Only stdout is parsed; a warning on stderr cannot forge a status.
		{"stderr is not parsed", pwshtest.Exit("NotSigned|\r\n", "Valid|"+thumb, 0), false, "", nil},
		{"unsigned", pwshtest.Stdout("NotSigned|\r\n"), false, "", nil},
		{"verifier failed carries what it printed", pwshtest.Exit("partial", "Get-AuthenticodeSignature : Cannot find path", 1), false, "",
			[]string{"exit status 1", "Cannot find path", "partial"}},
		{"timeout", pwshtest.Fail(pwsh.ErrTimeout), false, "", []string{"timed out"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &pwshtest.Fake{Reply: tt.reply}
			path := `C:\tmp\a b;$(evil).exe`
			valid, gotThumb, err := Verify(context.Background(), fake.Run, "NL_TEST_PATH", path)
			if valid != tt.wantValid || gotThumb != tt.wantThumb {
				t.Fatalf("Verify = %v, %q, %v; want %v, %q", valid, gotThumb, err, tt.wantValid, tt.wantThumb)
			}
			if tt.wantErrHas == nil && err != nil {
				t.Fatalf("Verify error = %v", err)
			}
			for _, part := range tt.wantErrHas {
				if err == nil || !strings.Contains(err.Error(), part) {
					t.Fatalf("Verify error = %v, want it to contain %q", err, part)
				}
			}
			if calls := fake.Calls(); !reflect.DeepEqual(calls, []pwsh.Script{Script("NL_TEST_PATH", path)}) {
				t.Fatalf("calls = %#v", calls)
			}
		})
	}
	if _, _, err := Verify(context.Background(), (&pwshtest.Fake{Reply: pwshtest.Fail(pwsh.ErrTimeout)}).Run, "NL_TEST_PATH", "x"); !errors.Is(err, pwsh.ErrTimeout) {
		t.Fatalf("Verify must wrap the runner error, got %v", err)
	}
}
