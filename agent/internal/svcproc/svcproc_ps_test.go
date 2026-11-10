// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type psCall struct {
	timeout time.Duration
	arg     string
	script  string
}

// fakePS returns a psRunner that records its call and replies with captured
// PowerShell output.
func fakePS(out string, err error, calls *[]psCall) psRunner {
	return func(_ context.Context, timeout time.Duration, arg, script string) ([]byte, error) {
		*calls = append(*calls, psCall{timeout: timeout, arg: arg, script: script})
		return []byte(out), err
	}
}

func assertOneCall(t *testing.T, calls []psCall, want psCall) {
	t.Helper()
	if len(calls) != 1 {
		t.Fatalf("runner called %d times, want 1", len(calls))
	}
	if calls[0] != want {
		t.Fatalf("runner call = %+v, want %+v", calls[0], want)
	}
}

func TestPSListServices(t *testing.T) {
	spooler := ServiceInfo{Name: "Spooler", DisplayName: "Print Spooler", State: "Running", StartMode: "Auto", Account: "LocalSystem"}
	w32 := ServiceInfo{Name: "W32Time", DisplayName: "Windows Time", State: "Stopped", StartMode: "Manual", Account: `NT AUTHORITY\LocalService`}
	cases := []struct {
		name    string
		out     string
		err     error
		want    []ServiceInfo
		wantErr string
	}{
		{"array", `[{"Name":"Spooler","DisplayName":"Print Spooler","State":"Running","StartMode":"Auto","StartName":"LocalSystem"},` +
			`{"Name":"W32Time","DisplayName":"Windows Time","State":"Stopped","StartMode":"Manual","StartName":"NT AUTHORITY\\LocalService"}]`,
			nil, []ServiceInfo{spooler, w32}, ""},
		{"single object", "\r\n{\"Name\":\"Spooler\",\"DisplayName\":\"Print Spooler\",\"State\":\"Running\",\"StartMode\":\"Auto\",\"StartName\":\"LocalSystem\"}\r\n",
			nil, []ServiceInfo{spooler}, ""},
		{"empty", "", nil, []ServiceInfo{}, ""},
		{"null account", `{"Name":"X","DisplayName":"X","State":"Stopped","StartMode":"Disabled","StartName":null}`,
			nil, []ServiceInfo{{Name: "X", DisplayName: "X", State: "Stopped", StartMode: "Disabled"}}, ""},
		{"malformed", `{"Name":`, nil, nil, "invalid character"},
		{"exec failure carries output", "Get-CimInstance : Access denied\r\n", errors.New("exit status 1"), nil, "exit status 1: Get-CimInstance : Access denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []psCall
			got, err := psListServices(context.Background(), fakePS(tc.out, tc.err, &calls))
			assertOneCall(t, calls, psCall{timeout: listTimeout, script: listServicesScript})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("services = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestPSListProcesses(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		err     error
		want    []ProcessInfo
		wantErr string
	}{
		{"array", `[{"ProcessId":0,"Name":"System Idle Process"},{"ProcessId":4242,"Name":"notepad.exe"}]`,
			nil, []ProcessInfo{{PID: 0, Name: "System Idle Process"}, {PID: 4242, Name: "notepad.exe"}}, ""},
		{"single object", `{"ProcessId":4,"Name":"System"}`, nil, []ProcessInfo{{PID: 4, Name: "System"}}, ""},
		{"empty", "  \r\n", nil, []ProcessInfo{}, ""},
		{"wrong type", `{"ProcessId":"four","Name":"System"}`, nil, nil, "cannot unmarshal"},
		{"exec failure", "boom", errors.New("exit status 1"), nil, "exit status 1: boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []psCall
			got, err := psListProcesses(context.Background(), fakePS(tc.out, tc.err, &calls))
			assertOneCall(t, calls, psCall{timeout: listTimeout, script: listProcessesScript})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("processes = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestControlServiceScript(t *testing.T) {
	cases := []struct {
		action, verb string
	}{
		{ActionStart, "Start-Service -Name $env:NL_ARG"},
		{ActionStop, "Stop-Service -Name $env:NL_ARG"},
		{ActionRestart, "Restart-Service -Name $env:NL_ARG"},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			script, err := controlServiceScript(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(script, "; "+tc.verb+"; ") {
				t.Fatalf("script missing %q: %s", tc.verb, script)
			}
			if !strings.HasPrefix(script, "$ErrorActionPreference='Stop'; ") || !strings.Contains(script, "NL_NOTFOUND") {
				t.Fatalf("script lost its guard: %s", script)
			}
			// Stopping must never cascade into dependent services.
			if strings.Contains(script, "-Force") {
				t.Fatalf("script uses -Force: %s", script)
			}
		})
	}
	if _, err := controlServiceScript("pause"); err == nil || err.Error() != `unsupported action "pause"` {
		t.Fatalf("unsupported action error = %v", err)
	}
}

func TestPSControlService(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		err     error
		want    string
		wantErr string
	}{
		{"running", "Running\r\n", nil, "Running", ""},
		{"warnings before status", "WARNING: Waiting for service 'Spooler' to start...\r\nRunning", nil, "Running", ""},
		{"not found", "NL_NOTFOUND", errors.New("exit status 3"), "", "service does not exist"},
		{"not found wins without exit error", "NL_NOTFOUND\r\n", nil, "", "service does not exist"},
		{"failure reports first line", "Stop-Service : Cannot stop service 'Spooler'\r\nAt line:1 char:1", errors.New("exit status 1"), "", "Stop-Service : Cannot stop service 'Spooler'"},
		{"failure without output", "", errors.New("exit status 1"), "", "service control failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []psCall
			got, err := psControlService(context.Background(), fakePS(tc.out, tc.err, &calls), "Spooler", ActionRestart)
			script, _ := controlServiceScript(ActionRestart)
			assertOneCall(t, calls, psCall{timeout: controlTimeout, arg: "Spooler", script: script})
			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("psControlService = (%q, %v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestPSControlServiceRejectsUnknownActionWithoutRunning(t *testing.T) {
	var calls []psCall
	if _, err := psControlService(context.Background(), fakePS("", nil, &calls), "Spooler", "pause"); err == nil {
		t.Fatal("unknown action succeeded")
	}
	if len(calls) != 0 {
		t.Fatalf("runner called for an unknown action: %+v", calls)
	}
}

// The target name/pid is bound to NL_ARG; it must never be spliced into the
// script text, so hostile names cannot change what PowerShell runs.
func TestPSTargetsNeverEnterScriptText(t *testing.T) {
	hostile := `Spooler'; Remove-Item -Recurse C:\; '`
	var calls []psCall
	run := fakePS("Running", nil, &calls)
	for _, action := range []string{ActionStart, ActionStop, ActionRestart} {
		_, _ = psControlService(context.Background(), run, hostile, action)
	}
	_, _ = psProcessName(context.Background(), run, 31337)
	_ = psTerminateProcess(context.Background(), run, 31337)
	if len(calls) != 5 {
		t.Fatalf("runner called %d times, want 5", len(calls))
	}
	for _, call := range calls {
		if strings.Contains(call.script, hostile) || strings.Contains(call.script, "31337") {
			t.Fatalf("target leaked into script: %s", call.script)
		}
		if !strings.Contains(call.script, "$env:NL_ARG") {
			t.Fatalf("script does not read NL_ARG: %s", call.script)
		}
	}
	if calls[0].arg != hostile || calls[3].arg != "31337" || calls[4].arg != "31337" {
		t.Fatalf("targets not passed via arg: %+v", calls)
	}
}

func TestPSProcessName(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		err     error
		want    string
		wantErr bool
	}{
		{"base name gets exe", "notepad\r\n", nil, "notepad.exe", false},
		{"dotted name kept", "svchost.exe", nil, "svchost.exe", false},
		{"last line wins", "WARNING: noise\r\nlsass", nil, "lsass.exe", false},
		{"not found marker", "NL_NOTFOUND", nil, "", true},
		{"empty", "  ", nil, "", true},
		{"exec failure", "notepad", errors.New("exit status 1"), "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []psCall
			got, err := psProcessName(context.Background(), fakePS(tc.out, tc.err, &calls), 4242)
			assertOneCall(t, calls, psCall{timeout: listTimeout, arg: "4242", script: processNameScript})
			if tc.wantErr {
				if err == nil || err.Error() != "process not found" {
					t.Fatalf("error = %v, want process not found", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("psProcessName = (%q, %v), want %q", got, err, tc.want)
			}
		})
	}
}

func TestPSTerminateProcess(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		err     error
		wantErr string
	}{
		{"success", "", nil, ""},
		{"success ignores output", "noise", nil, ""},
		{"failure reports first line", "Stop-Process : Access is denied\r\nAt line:1", errors.New("exit status 1"), "Stop-Process : Access is denied"},
		{"failure without output", "", errors.New("exit status 1"), "service control failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls []psCall
			err := psTerminateProcess(context.Background(), fakePS(tc.out, tc.err, &calls), 4242)
			assertOneCall(t, calls, psCall{timeout: controlTimeout, arg: "4242", script: terminateScript})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || err.Error() != tc.wantErr {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
