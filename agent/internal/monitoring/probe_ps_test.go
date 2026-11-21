// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

// fakePS returns a Fake that replies with captured PowerShell stdout, or fails
// with err when it is set.
func fakePS(out string, err error) *pwshtest.Fake {
	if err != nil {
		return &pwshtest.Fake{Reply: pwshtest.Fail(err)}
	}
	return &pwshtest.Fake{Reply: pwshtest.Stdout(out)}
}

func onlyCall(t *testing.T, fake *pwshtest.Fake) pwsh.Script {
	t.Helper()
	calls := fake.Calls()
	if len(calls) != 1 {
		t.Fatalf("runner called %d times, want 1", len(calls))
	}
	if calls[0].Timeout != probeTimeout {
		t.Fatalf("probe timeout = %s, want %s", calls[0].Timeout, probeTimeout)
	}
	return calls[0]
}

// Policy-supplied mount points and service names travel as environment
// arguments; the script text is a constant they can never reach.
func TestProbeValuesNeverEnterScriptText(t *testing.T) {
	hostile := `x'; Remove-Item -Recurse C:\; 'y`
	cases := []struct {
		name   string
		probe  func(*pwshtest.Fake)
		envVar string
	}{
		{"disk", func(f *pwshtest.Fake) { diskPercent(context.Background(), f.Run, hostile) }, "NL_MOUNT"},
		{"service", func(f *pwshtest.Fake) { serviceState(context.Background(), f.Run, hostile) }, "NL_SERVICE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS("", nil)
			tc.probe(fake)
			call := onlyCall(t, fake)
			if strings.Contains(call.Body, hostile) || strings.Contains(call.Body, "Remove-Item") {
				t.Fatalf("value leaked into script: %s", call.Body)
			}
			if !strings.Contains(call.Body, "$env:"+tc.envVar) || call.Env[tc.envVar] != hostile || len(call.Env) != 1 {
				t.Fatalf("value not passed via %s: %+v", tc.envVar, call)
			}
		})
	}
}

func TestDiskPercent(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		err       error
		want      float64
		wantOK    bool
		wantCause string
	}{
		{"invariant decimal", "42.5", nil, 42.5, true, "sample_collected"},
		{"locale decimal comma", "87,25", nil, 87.25, true, "sample_collected"},
		{"integer", "100", nil, 100, true, "sample_collected"},
		{"zero", "0", nil, 0, true, "sample_collected"},
		{"missing disk", "missing", nil, 0, false, "disk_not_found"},
		{"empty output", "", nil, 0, false, "disk_probe_invalid"},
		{"garbage", "Get-CimInstance : Access denied", nil, 0, false, "disk_probe_invalid"},
		{"exec failure", "", errors.New("exit status 1"), 0, false, "disk_probe_failed"},
		{"failure wins over output", "42.5", errors.New("timeout"), 0, false, "disk_probe_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.out, tc.err)
			got, ok, cause := diskPercent(context.Background(), fake.Run, "C:")
			if got != tc.want || ok != tc.wantOK || cause != tc.wantCause {
				t.Fatalf("diskPercent = (%v, %v, %q), want (%v, %v, %q)", got, ok, cause, tc.want, tc.wantOK, tc.wantCause)
			}
			if call := onlyCall(t, fake); call.Body != diskPercentScript || call.Env["NL_MOUNT"] != "C:" {
				t.Fatalf("unexpected disk call: %+v", call)
			}
		})
	}
}

func TestServiceState(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		err       error
		want      string
		wantOK    bool
		wantCause string
	}{
		{"running", "running", nil, "running", true, "sample_collected"},
		{"mixed case normalized", "Stopped", nil, "stopped", true, "sample_collected"},
		{"absent", "absent", nil, "absent", true, "sample_collected"},
		{"empty", "", nil, "", false, "service_probe_invalid"},
		{"exec failure", "running", errors.New("exit status 1"), "", false, "service_probe_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.out, tc.err)
			got, ok, cause := serviceState(context.Background(), fake.Run, "Spooler")
			if got != tc.want || ok != tc.wantOK || cause != tc.wantCause {
				t.Fatalf("serviceState = (%q, %v, %q), want (%q, %v, %q)", got, ok, cause, tc.want, tc.wantOK, tc.wantCause)
			}
			if call := onlyCall(t, fake); call.Body != serviceStateScript || call.Env["NL_SERVICE"] != "Spooler" {
				t.Fatalf("unexpected service call: %+v", call)
			}
		})
	}
}

func TestRebootPending(t *testing.T) {
	cases := []struct {
		name      string
		out       string
		err       error
		want      RebootStatus
		wantOK    bool
		wantCause string
	}{
		{"nothing pending", "false\nfalse\nfalse\n-1", nil, RebootStatus{}, true, "sample_collected"},
		{"windows update with renames", "false\ntrue\ntrue\n3", nil,
			RebootStatus{Sources: RebootSources{WindowsUpdate: true, PendingFileRename: true}, PendingFileRenameCount: 3, CountKnown: true},
			true, "sample_collected"},
		{"crlf output", "true\r\nfalse\r\nfalse\r\n0", nil,
			RebootStatus{Sources: RebootSources{ComponentBasedServicing: true}, CountKnown: true},
			true, "sample_collected"},
		{"too few lines", "true\nfalse", nil, RebootStatus{}, false, "reboot_probe_invalid"},
		{"empty", "", nil, RebootStatus{}, false, "reboot_probe_invalid"},
		{"exec failure", "", errors.New("exit status 1"), RebootStatus{}, false, "reboot_probe_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := fakePS(tc.out, tc.err)
			got, ok, cause := rebootPending(context.Background(), fake.Run)
			script := onlyCall(t, fake).Body
			if got != tc.want || ok != tc.wantOK || cause != tc.wantCause {
				t.Fatalf("rebootPending = (%+v, %v, %q), want (%+v, %v, %q)", got, ok, cause, tc.want, tc.wantOK, tc.wantCause)
			}
			for _, key := range []string{"Component Based Servicing", "WindowsUpdate", "PendingFileRenameOperations"} {
				if !strings.Contains(script, key) {
					t.Fatalf("reboot script lost %q", key)
				}
			}
		})
	}
}
