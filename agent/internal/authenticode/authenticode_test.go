// SPDX-License-Identifier: AGPL-3.0-only
package authenticode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestCommandKeepsThePathOutOfTheScript(t *testing.T) {
	name, args := Command("NL_TEST_PATH")
	if name != "powershell.exe" {
		t.Fatalf("name = %q", name)
	}
	if len(args) != 4 || !reflect.DeepEqual(args[:3], []string{"-NoProfile", "-NonInteractive", "-Command"}) {
		t.Fatalf("args = %#v", args)
	}
	if !strings.Contains(args[3], "Get-AuthenticodeSignature -LiteralPath $env:NL_TEST_PATH;") {
		t.Fatalf("script does not read the path from the environment: %q", args[3])
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

type call struct {
	env  []string
	name string
	args []string
}

func TestVerify(t *testing.T) {
	runErr := errors.New("exit status 1: Get-AuthenticodeSignature : Cannot find path")
	tests := []struct {
		name      string
		out       string
		err       error
		wantValid bool
		wantThumb string
		wantErr   error
	}{
		{"signed", "Valid|0123456789ABCDEF0123456789ABCDEF01234567\r\n", nil, true, "0123456789ABCDEF0123456789ABCDEF01234567", nil},
		{"unsigned", "NotSigned|\r\n", nil, false, "", nil},
		{"verifier failed", "", runErr, false, "", runErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []call
			run := func(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("verification must run under a deadline")
				}
				calls = append(calls, call{env, name, args})
				return []byte(tt.out), tt.err
			}
			valid, thumb, err := Verify(context.Background(), run, "NL_TEST_PATH", `C:\tmp\a b;$(evil).exe`)
			if valid != tt.wantValid || thumb != tt.wantThumb || !errors.Is(err, tt.wantErr) {
				t.Fatalf("Verify = %v, %q, %v; want %v, %q, %v", valid, thumb, err, tt.wantValid, tt.wantThumb, tt.wantErr)
			}
			wantName, wantArgs := Command("NL_TEST_PATH")
			want := []call{{[]string{`NL_TEST_PATH=C:\tmp\a b;$(evil).exe`}, wantName, wantArgs}}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %#v, want %#v", calls, want)
			}
		})
	}
}

// TestHelperProcess is not a real test: Exec's tests start the test binary as
// a child process that lands here and behaves as the parent asked.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("AUTHENTICODE_HELPER")
	if mode == "" {
		return
	}
	switch mode {
	case "echo-env":
		fmt.Fprint(os.Stdout, os.Getenv("NL_TEST_PATH"))
		fmt.Fprint(os.Stderr, "noise on stderr")
		os.Exit(0)
	case "fail":
		fmt.Fprint(os.Stdout, "partial")
		fmt.Fprint(os.Stderr, "access denied")
		os.Exit(3)
	}
	os.Exit(2)
}

func runHelper(mode string, env ...string) ([]byte, error) {
	env = append([]string{"AUTHENTICODE_HELPER=" + mode}, env...)
	return Exec(context.Background(), env, os.Args[0], "-test.run=^TestHelperProcess$")
}

func TestExecReturnsStdoutOnlyAndPassesEnv(t *testing.T) {
	out, err := runHelper("echo-env", "NL_TEST_PATH=C:\\x.exe")
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if string(out) != `C:\x.exe` {
		t.Fatalf("stdout = %q; stderr must not be mixed into what is parsed", out)
	}
}

func TestExecFailureCarriesWhatTheProcessPrinted(t *testing.T) {
	_, err := runHelper("fail")
	if err == nil {
		t.Fatal("a non-zero exit must be an error")
	}
	if !strings.Contains(err.Error(), "access denied") || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("error %q must carry stderr and stdout", err)
	}
}

func TestExecFailsWhenTheProgramIsMissing(t *testing.T) {
	if _, err := Exec(context.Background(), nil, "nodelink-no-such-program"); err == nil {
		t.Fatal("a missing program must be an error")
	}
}
