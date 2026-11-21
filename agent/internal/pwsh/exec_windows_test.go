//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package pwsh

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

// These run the real powershell.exe, so they are the coverage for the flag
// set, env passing, timeout kill and stream separation every package relies on.

func run(t *testing.T, s Script) (Result, error) {
	t.Helper()
	if s.Timeout == 0 {
		s.Timeout = 60 * time.Second
	}
	return Exec(context.Background(), s)
}

func TestExecPassesTheHardenedFlags(t *testing.T) {
	res, err := run(t, Script{Body: "[Environment]::CommandLine"})
	if err != nil {
		t.Fatalf("Exec: %v (stderr %q)", err, res.Stderr)
	}
	line := string(res.Stdout)
	for _, flag := range []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy Bypass", "-Command"} {
		if !strings.Contains(line, flag) {
			t.Fatalf("command line %q lacks %s", line, flag)
		}
	}
}

// The value comes back base64-encoded so the console output code page cannot
// mangle it on the way out; what is checked is what PowerShell itself saw.
const echoArg = "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($env:NL_ARG))"

func TestExecEnvArgumentRoundTripsUnchanged(t *testing.T) {
	hostile := `it's "quoted" $(Write-Output pwned); ` + "`n ünïcødé 😀 \\ %PATH%"
	for _, encoded := range []bool{false, true} {
		res, err := run(t, Script{Body: echoArg, Env: map[string]string{"NL_ARG": hostile}, Encoded: encoded})
		if err != nil {
			t.Fatalf("encoded=%v: Exec: %v (stderr %q)", encoded, err, res.Stderr)
		}
		got, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(res.Stdout)))
		if err != nil {
			t.Fatalf("encoded=%v: stdout %q is not base64: %v", encoded, res.Stdout, err)
		}
		if string(got) != hostile {
			t.Fatalf("encoded=%v: PowerShell saw %q, want %q", encoded, got, hostile)
		}
	}
}

func TestExecEncodedBodyKeepsNonASCIIText(t *testing.T) {
	res, err := run(t, Script{Body: "[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('ünï 😀'))", Encoded: true})
	if err != nil {
		t.Fatalf("Exec: %v (stderr %q)", err, res.Stderr)
	}
	got, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(res.Stdout)))
	if string(got) != "ünï 😀" {
		t.Fatalf("encoded body produced %q", got)
	}
}

func TestExecSeparatesStderrAndReportsTheExitCode(t *testing.T) {
	res, err := run(t, Script{Body: "Write-Output 'to-stdout'; [Console]::Error.WriteLine('to-stderr'); exit 3"})
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 3 || err.Error() != "exit status 3" {
		t.Fatalf("err = %v, want exit status 3", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("ExitCode = %d, want 3", res.ExitCode)
	}
	if got := strings.TrimSpace(string(res.Stdout)); got != "to-stdout" {
		t.Fatalf("Stdout = %q", res.Stdout)
	}
	if got := strings.TrimSpace(string(res.Stderr)); got != "to-stderr" {
		t.Fatalf("Stderr = %q", res.Stderr)
	}
}

func TestExecKillsARunThatOutlivesItsTimeout(t *testing.T) {
	start := time.Now()
	res, err := run(t, Script{Body: "Write-Output started; Start-Sleep -Seconds 60", Timeout: 3 * time.Second})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("timed-out run took %s to return", elapsed)
	}
	if !strings.Contains(string(res.Stdout), "started") {
		t.Fatalf("output written before the kill was lost: %q", res.Stdout)
	}
}

func TestExecReturnsTheParentContextErrorOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(2*time.Second, cancel)
	_, err := Exec(ctx, Script{Body: "Start-Sleep -Seconds 60", Timeout: time.Minute})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestExecDropsAnInheritedPSModulePath(t *testing.T) {
	t.Setenv("PSModulePath", `C:\nodelink-bogus-modules`)
	res, err := run(t, Script{Body: "(Get-CimInstance Win32_OperatingSystem).Caption; $env:PSModulePath"})
	if err != nil {
		t.Fatalf("Exec with a foreign PSModulePath: %v (stderr %q)", err, res.Stderr)
	}
	if strings.Contains(string(res.Stdout), "nodelink-bogus") {
		t.Fatalf("child inherited PSModulePath: %q", res.Stdout)
	}
}

func TestExecRefusesAScriptWithoutATimeout(t *testing.T) {
	if _, err := Exec(context.Background(), Script{Body: "1"}); err == nil {
		t.Fatal("Exec ran a script with no timeout")
	}
}
