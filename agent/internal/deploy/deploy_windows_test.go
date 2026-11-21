//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/authenticode"
	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

func fakeProcess(t *testing.T, code int, err error) *[]processCall {
	t.Helper()
	orig := runProcess
	var calls []processCall
	runProcess = func(_ context.Context, name string, args ...string) (int, error) {
		calls = append(calls, processCall{name, append([]string(nil), args...)})
		return code, err
	}
	t.Cleanup(func() { runProcess = orig })
	return &calls
}

func fakePowerShell(t *testing.T, reply func(pwsh.Script) (pwsh.Result, error)) *pwshtest.Fake {
	t.Helper()
	orig := runPowerShell
	fake := &pwshtest.Fake{Reply: reply}
	runPowerShell = fake.Run
	t.Cleanup(func() { runPowerShell = orig })
	return fake
}

func TestPlatformRunInstallerArgv(t *testing.T) {
	tests := []struct {
		name string
		typ  string
		path string
		args []string
		want processCall
	}{
		{"msi", InstallerMSI, `C:\Temp\app.msi`, []string{"ALLUSERS=1"},
			processCall{"msiexec.exe", []string{"/i", `C:\Temp\app.msi`, "/qn", "/norestart", "ALLUSERS=1"}}},
		{"exe", InstallerEXE, `C:\Temp\setup.exe`, []string{"/S"},
			processCall{`C:\Temp\setup.exe`, []string{"/S"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := fakeProcess(t, 0, nil)
			code, err := platformRunInstaller(context.Background(), tt.typ, tt.path, tt.args, time.Minute)
			if code != 0 || err != nil {
				t.Fatalf("got %d, %v", code, err)
			}
			if !reflect.DeepEqual(*calls, []processCall{tt.want}) {
				t.Fatalf("calls = %#v, want %#v", *calls, tt.want)
			}
		})
	}
}

func TestPlatformRunInstallerRefusesUnknownTypeWithoutStarting(t *testing.T) {
	calls := fakeProcess(t, 0, nil)
	if _, err := platformRunInstaller(context.Background(), "appx", `C:\Temp\x.appx`, nil, time.Minute); err == nil {
		t.Fatal("an unknown installer type must be refused")
	}
	if len(*calls) != 0 {
		t.Fatalf("nothing may start for an unknown type: %#v", *calls)
	}
}

func TestPlatformVerifyAuthenticode(t *testing.T) {
	tests := []struct {
		name      string
		reply     func(pwsh.Script) (pwsh.Result, error)
		wantValid bool
		wantThumb string
		wantErr   bool
	}{
		{"valid", pwshtest.Stdout("Valid|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"), true, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"not signed", pwshtest.Stdout("NotSigned|\r\n"), false, "", false},
		{"powershell failed", pwshtest.Exit("", "denied", 1), false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := fakePowerShell(t, tt.reply)
			valid, thumb, err := platformVerifyAuthenticode(context.Background(), `C:\Temp\app.msi`)
			if valid != tt.wantValid || thumb != tt.wantThumb || (err != nil) != tt.wantErr {
				t.Fatalf("got %v, %q, %v", valid, thumb, err)
			}
			want := []pwsh.Script{authenticode.Script(pathEnvVar, `C:\Temp\app.msi`)}
			if calls := fake.Calls(); !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %#v", calls)
			}
		})
	}
}

func TestPlatformReadProductCode(t *testing.T) {
	fake := fakePowerShell(t, pwshtest.Stdout("{2B7C2A5E-1F1D-4E4B-9C61-0D5A3B1E7F10}\r\n"))
	if got := platformReadProductCode(context.Background(), `C:\Temp\app.msi`); got != "{2B7C2A5E-1F1D-4E4B-9C61-0D5A3B1E7F10}" {
		t.Fatalf("got %q", got)
	}
	if calls := fake.Calls(); len(calls) != 1 || calls[0].Body != productCodeScript {
		t.Fatalf("calls = %#v", calls)
	}
}
