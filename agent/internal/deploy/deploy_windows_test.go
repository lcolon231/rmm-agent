//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/authenticode"
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

func fakePowerShell(t *testing.T, out string, err error) *[]psCall {
	t.Helper()
	orig := runPowerShell
	var calls []psCall
	runPowerShell = func(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
		calls = append(calls, psCall{env, name, append([]string(nil), args...)})
		return []byte(out), err
	}
	t.Cleanup(func() { runPowerShell = orig })
	return &calls
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
		out       string
		err       error
		wantValid bool
		wantThumb string
		wantErr   bool
	}{
		{"valid", "Valid|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n", nil, true, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"not signed", "NotSigned|\r\n", nil, false, "", false},
		{"powershell failed", "", errors.New("exit status 1"), false, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := fakePowerShell(t, tt.out, tt.err)
			valid, thumb, err := platformVerifyAuthenticode(context.Background(), `C:\Temp\app.msi`)
			if valid != tt.wantValid || thumb != tt.wantThumb || (err != nil) != tt.wantErr {
				t.Fatalf("got %v, %q, %v", valid, thumb, err)
			}
			name, args := authenticode.Command(pathEnvVar)
			want := []psCall{{[]string{`NL_DEPLOY_PATH=C:\Temp\app.msi`}, name, args}}
			if !reflect.DeepEqual(*calls, want) {
				t.Fatalf("calls = %#v", *calls)
			}
		})
	}
}

func TestPlatformReadProductCode(t *testing.T) {
	calls := fakePowerShell(t, "{2B7C2A5E-1F1D-4E4B-9C61-0D5A3B1E7F10}\r\n", nil)
	if got := platformReadProductCode(context.Background(), `C:\Temp\app.msi`); got != "{2B7C2A5E-1F1D-4E4B-9C61-0D5A3B1E7F10}" {
		t.Fatalf("got %q", got)
	}
	if len(*calls) != 1 || (*calls)[0].name != "powershell.exe" {
		t.Fatalf("calls = %#v", *calls)
	}
}
