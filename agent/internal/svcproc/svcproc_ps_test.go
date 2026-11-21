// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

// reply describes what the fake PowerShell printed and how it exited.
type reply struct {
	stdout, stderr string
	code           int
}

func fakePS(r reply) *pwshtest.Fake {
	return &pwshtest.Fake{Reply: pwshtest.Exit(r.stdout, r.stderr, r.code)}
}

func assertOneCall(t *testing.T, fake *pwshtest.Fake, want pwsh.Script) {
	t.Helper()
	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("runner called %d times, want 1", len(calls))
	}
	if !reflect.DeepEqual(calls[0], want) {
		t.Fatalf("runner call = %+v, want %+v", calls[0], want)
	}
}

func arg(v string) map[string]string { return map[string]string{"NL_ARG": v} }

func TestPSListServices(t *testing.T) {
	spooler := ServiceInfo{Name: "Spooler", DisplayName: "Print Spooler", State: "Running", StartMode: "Auto", Account: "LocalSystem"}
	w32 := ServiceInfo{Name: "W32Time", DisplayName: "Windows Time", State: "Stopped", StartMode: "Manual", Account: `NT AUTHORITY\LocalService`}
	cases := []struct {
		name    string
		reply   reply
		want    []ServiceInfo
		wantErr string
	}{
		{"array", reply{stdout: `[{"Name":"Spooler","DisplayName":"Print Spooler","State":"Running","StartMode":"Auto","StartName":"LocalSystem"},` +
			`{"Name":"W32Time","DisplayName":"Windows Time","State":"Stopped","StartMode":"Manual","StartName":"NT AUTHORITY\\LocalService"}]`},
			[]ServiceInfo{spooler, w32}, ""},
		{"single object", reply{stdout: "\r\n{\"Name\":\"Spooler\",\"DisplayName\":\"Print Spooler\",\"State\":\"Running\",\"StartMode\":\"Auto\",\"StartName\":\"LocalSystem\"}\r\n"},
			[]ServiceInfo{spooler}, ""},
		{"empty", reply{}, []ServiceInfo{}, ""},
		{"null account", reply{stdout: `{"Name":"X","DisplayName":"X","State":"Stopped","StartMode":"Disabled","StartName":null}`},
			[]ServiceInfo{{Name: "X", DisplayName: "X", State: "Stopped", StartMode: "Disabled"}}, ""},
		{"malformed", reply{stdout: `{"Name":`}, nil, "invalid character"},
		// A warning on stderr must not corrupt the JSON on stdout.
		{"stderr noise ignored on success", reply{stdout: `{"Name":"X"}`, stderr: "WARNING: slow provider"}, []ServiceInfo{{Name: "X"}}, ""},
		{"exec failure carries stderr", reply{stderr: "Get-CimInstance : Access denied\r\n", code: 1}, nil, "exit status 1: Get-CimInstance : Access denied"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.reply)
			got, err := psListServices(context.Background(), fake.Run)
			assertOneCall(t, fake, pwsh.Script{Body: listServicesScript, Timeout: listTimeout})
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
		reply   reply
		want    []ProcessInfo
		wantErr string
	}{
		{"array", reply{stdout: `[{"ProcessId":0,"Name":"System Idle Process"},{"ProcessId":4242,"Name":"notepad.exe"}]`},
			[]ProcessInfo{{PID: 0, Name: "System Idle Process"}, {PID: 4242, Name: "notepad.exe"}}, ""},
		{"single object", reply{stdout: `{"ProcessId":4,"Name":"System"}`}, []ProcessInfo{{PID: 4, Name: "System"}}, ""},
		{"empty", reply{stdout: "  \r\n"}, []ProcessInfo{}, ""},
		{"wrong type", reply{stdout: `{"ProcessId":"four","Name":"System"}`}, nil, "cannot unmarshal"},
		{"exec failure", reply{stdout: "boom", code: 1}, nil, "exit status 1: boom"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.reply)
			got, err := psListProcesses(context.Background(), fake.Run)
			assertOneCall(t, fake, pwsh.Script{Body: listProcessesScript, Timeout: listTimeout})
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
		reply   reply
		want    string
		wantErr string
	}{
		{"running", reply{stdout: "Running\r\n"}, "Running", ""},
		{"warnings before status", reply{stdout: "WARNING: Waiting for service 'Spooler' to start...\r\nRunning"}, "Running", ""},
		{"warning on stderr", reply{stdout: "Running", stderr: "WARNING: Waiting for service 'Spooler' to start..."}, "Running", ""},
		{"not found", reply{stdout: "NL_NOTFOUND", code: 3}, "", "service does not exist"},
		{"not found wins without exit error", reply{stdout: "NL_NOTFOUND\r\n"}, "", "service does not exist"},
		{"failure reports first stderr line", reply{stderr: "Stop-Service : Cannot stop service 'Spooler'\r\nAt line:1 char:1", code: 1}, "", "Stop-Service : Cannot stop service 'Spooler'"},
		{"failure falls back to stdout", reply{stdout: "Stop-Service : Cannot stop service 'Spooler'", code: 1}, "", "Stop-Service : Cannot stop service 'Spooler'"},
		{"failure without output", reply{code: 1}, "", "service control failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.reply)
			got, err := psControlService(context.Background(), fake.Run, "Spooler", ActionRestart)
			script, _ := controlServiceScript(ActionRestart)
			assertOneCall(t, fake, pwsh.Script{Body: script, Env: arg("Spooler"), Timeout: controlTimeout})
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
	fake := fakePS(reply{})
	if _, err := psControlService(context.Background(), fake.Run, "Spooler", "pause"); err == nil {
		t.Fatal("unknown action succeeded")
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Fatalf("runner called for an unknown action: %+v", calls)
	}
}

// The target name/pid is bound to NL_ARG; it must never be spliced into the
// script text, so hostile names cannot change what PowerShell runs.
func TestPSTargetsNeverEnterScriptText(t *testing.T) {
	hostile := `Spooler'; Remove-Item -Recurse C:\; '`
	fake := fakePS(reply{stdout: "Running"})
	for _, action := range []string{ActionStart, ActionStop, ActionRestart} {
		_, _ = psControlService(context.Background(), fake.Run, hostile, action)
	}
	_, _ = psProcessName(context.Background(), fake.Run, 31337)
	_ = psTerminateProcess(context.Background(), fake.Run, 31337)
	calls := fake.Calls()
	if len(calls) != 5 {
		t.Fatalf("runner called %d times, want 5", len(calls))
	}
	for _, call := range calls {
		if strings.Contains(call.Body, hostile) || strings.Contains(call.Body, "31337") {
			t.Fatalf("target leaked into script: %s", call.Body)
		}
		if !strings.Contains(call.Body, "$env:NL_ARG") {
			t.Fatalf("script does not read NL_ARG: %s", call.Body)
		}
	}
	if calls[0].Env["NL_ARG"] != hostile || calls[3].Env["NL_ARG"] != "31337" || calls[4].Env["NL_ARG"] != "31337" {
		t.Fatalf("targets not passed via NL_ARG: %+v", calls)
	}
}

func TestPSProcessName(t *testing.T) {
	cases := []struct {
		name    string
		reply   reply
		want    string
		wantErr bool
	}{
		{"base name gets exe", reply{stdout: "notepad\r\n"}, "notepad.exe", false},
		{"dotted name kept", reply{stdout: "svchost.exe"}, "svchost.exe", false},
		{"last line wins", reply{stdout: "WARNING: noise\r\nlsass"}, "lsass.exe", false},
		{"stderr noise ignored", reply{stdout: "lsass", stderr: "WARNING: noise"}, "lsass.exe", false},
		{"not found marker", reply{stdout: "NL_NOTFOUND"}, "", true},
		{"empty", reply{stdout: "  "}, "", true},
		{"exec failure", reply{stdout: "notepad", code: 1}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.reply)
			got, err := psProcessName(context.Background(), fake.Run, 4242)
			assertOneCall(t, fake, pwsh.Script{Body: processNameScript, Env: arg("4242"), Timeout: listTimeout})
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
		reply   reply
		wantErr string
	}{
		{"success", reply{}, ""},
		{"success ignores output", reply{stdout: "noise"}, ""},
		{"failure reports first stderr line", reply{stderr: "Stop-Process : Access is denied\r\nAt line:1", code: 1}, "Stop-Process : Access is denied"},
		{"failure without output", reply{code: 1}, "service control failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.reply)
			err := psTerminateProcess(context.Background(), fake.Run, 4242)
			assertOneCall(t, fake, pwsh.Script{Body: terminateScript, Env: arg("4242"), Timeout: controlTimeout})
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
