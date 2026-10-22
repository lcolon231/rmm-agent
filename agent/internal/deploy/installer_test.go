// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestInstallerCommand(t *testing.T) {
	tests := []struct {
		name     string
		typ      string
		path     string
		args     []string
		wantName string
		wantArgv []string
	}{
		{"msi without args", InstallerMSI, `C:\tmp\app.msi`, nil,
			"msiexec.exe", []string{"/i", `C:\tmp\app.msi`, "/qn", "/norestart"}},
		{"msi properties follow the fixed switches", InstallerMSI, `C:\tmp\app.msi`, []string{"ALLUSERS=1", "INSTALLDIR=C:\\Program Files\\App"},
			"msiexec.exe", []string{"/i", `C:\tmp\app.msi`, "/qn", "/norestart", "ALLUSERS=1", `INSTALLDIR=C:\Program Files\App`}},
		{"exe runs directly with operator args", InstallerEXE, `C:\tmp\setup.exe`, []string{"/S", "/D=C:\\App"},
			`C:\tmp\setup.exe`, []string{"/S", `/D=C:\App`}},
		{"exe without args", InstallerEXE, `C:\tmp\setup.exe`, nil,
			`C:\tmp\setup.exe`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, argv, err := installerCommand(tt.typ, tt.path, tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if name != tt.wantName || !reflect.DeepEqual(argv, tt.wantArgv) {
				t.Fatalf("got %q %#v, want %q %#v", name, argv, tt.wantName, tt.wantArgv)
			}
		})
	}
}

func TestInstallerCommandDoesNotAliasOperatorArgs(t *testing.T) {
	args := make([]string, 1, 4)
	args[0] = "/S"
	_, argv, _ := installerCommand(InstallerEXE, "setup.exe", args)
	argv[0] = "changed"
	if args[0] != "/S" {
		t.Fatal("the installer argv must not share storage with the payload")
	}
}

type processCall struct {
	name string
	args []string
}

func TestRunInstallerWith(t *testing.T) {
	launchErr := errors.New("file not found")
	tests := []struct {
		name     string
		typ      string
		code     int
		err      error
		wantCode int
		wantErr  string
		wantRuns int
	}{
		{"success", InstallerMSI, 0, nil, 0, "", 1},
		{"non-zero exit is an outcome", InstallerMSI, 1603, nil, 1603, "", 1},
		{"reboot-required exit", InstallerEXE, 3010, nil, 3010, "", 1},
		{"launch failure", InstallerEXE, -1, launchErr, -1, "file not found", 1},
		{"unsupported type never starts", "zip", 0, nil, -1, `unsupported installer type "zip"`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []processCall
			run := func(ctx context.Context, name string, args ...string) (int, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Error("the installer must run under the signed timeout")
				}
				calls = append(calls, processCall{name, args})
				return tt.code, tt.err
			}
			code, err := runInstallerWith(context.Background(), run, tt.typ, "pkg", []string{"/S"}, time.Minute)
			if code != tt.wantCode {
				t.Fatalf("code = %d, want %d", code, tt.wantCode)
			}
			if (err == nil) != (tt.wantErr == "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
			if len(calls) != tt.wantRuns {
				t.Fatalf("runs = %d, want %d", len(calls), tt.wantRuns)
			}
		})
	}
}

func TestRunInstallerWithReportsTimeout(t *testing.T) {
	run := func(ctx context.Context, _ string, _ ...string) (int, error) {
		<-ctx.Done()
		return -1, ctx.Err()
	}
	code, err := runInstallerWith(context.Background(), run, InstallerMSI, "pkg", nil, 20*time.Millisecond)
	if code != -1 || err == nil || !strings.Contains(err.Error(), "installer timed out after 20ms") {
		t.Fatalf("got %d, %v", code, err)
	}
}

type psCall struct {
	env  []string
	name string
	args []string
}

func TestReadProductCodeWith(t *testing.T) {
	tests := []struct {
		name string
		out  string
		err  error
		want string
	}{
		{"code with CRLF", "{2B7C2A5E-1F1D-4E4B-9C61-0D5A3B1E7F10}\r\n", nil, "{2B7C2A5E-1F1D-4E4B-9C61-0D5A3B1E7F10}"},
		{"no ProductCode row", "", nil, ""},
		{"read failure is not fatal", "partial", errors.New("COM error"), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []psCall
			run := func(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
				calls = append(calls, psCall{env, name, args})
				return []byte(tt.out), tt.err
			}
			if got := readProductCodeWith(context.Background(), run, `C:\tmp\app.msi`); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			want := []psCall{{
				[]string{`NL_DEPLOY_PATH=C:\tmp\app.msi`},
				"powershell.exe",
				[]string{"-NoProfile", "-NonInteractive", "-Command", productCodeScript},
			}}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %#v", calls)
			}
		})
	}
	if !strings.Contains(productCodeScript, "$env:NL_DEPLOY_PATH") {
		t.Fatal("the ProductCode script must read the path from the environment")
	}
}

// TestHelperProcess is not a real test: execProcess's tests start the test
// binary as a child that exits with the code the parent asked for.
func TestHelperProcess(t *testing.T) {
	code := os.Getenv("DEPLOY_HELPER_EXIT")
	if code == "" {
		return
	}
	n, _ := strconv.Atoi(code)
	os.Exit(n)
}

func TestExecProcessMapsExitCodes(t *testing.T) {
	// Below 256: POSIX truncates exit codes to a byte.
	for _, want := range []int{0, 3, 101} {
		t.Run(strconv.Itoa(want), func(t *testing.T) {
			t.Setenv("DEPLOY_HELPER_EXIT", strconv.Itoa(want))
			got, err := execProcess(context.Background(), os.Args[0], "-test.run=^TestHelperProcess$")
			if err != nil || got != want {
				t.Fatalf("execProcess = %d, %v; want %d", got, err, want)
			}
		})
	}
}

func TestExecProcessFailsWhenTheProgramIsMissing(t *testing.T) {
	code, err := execProcess(context.Background(), "nodelink-no-such-installer")
	if code != -1 || err == nil {
		t.Fatalf("execProcess = %d, %v; want -1 and an error", code, err)
	}
}
