// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakePS returns a psRunner that records the script it was given and replies
// with captured PowerShell output.
func fakePS(out string, err error, gotScript *string) psRunner {
	return func(_ context.Context, script string) (string, error) {
		if gotScript != nil {
			*gotScript = script
		}
		return out, err
	}
}

func TestPSQuote(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "C:", "C:"},
		{"empty", "", ""},
		{"single quote", "O'Brien", "O''Brien"},
		{"injection", "C:'; Remove-Item C:\\important; '", "C:''; Remove-Item C:\\important; ''"},
		{"double quote and dollar left alone", `"$env:X"`, `"$env:X"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := psQuote(tc.in); got != tc.want {
				t.Fatalf("psQuote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// singleQuotedLiterals returns the bodies of every '...' literal in script,
// honouring PowerShell's doubled-quote escape.
func singleQuotedLiterals(script string) []string {
	var out []string
	for i := 0; i < len(script); i++ {
		if script[i] != '\'' {
			continue
		}
		var b strings.Builder
		j := i + 1
		for ; j < len(script); j++ {
			if script[j] == '\'' {
				if j+1 < len(script) && script[j+1] == '\'' {
					b.WriteByte('\'')
					j++
					continue
				}
				break
			}
			b.WriteByte(script[j])
		}
		out = append(out, b.String())
		i = j
	}
	return out
}

func TestProbeScriptsKeepUntrustedValuesInsideOneLiteral(t *testing.T) {
	hostile := `x'; Remove-Item -Recurse C:\; 'y`
	cases := []struct {
		name   string
		script string
	}{
		{"disk", diskPercentScript(hostile)},
		{"service", serviceStateScript(hostile)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(tc.script, psQuote(hostile)) {
				t.Fatalf("script does not carry the quoted value: %s", tc.script)
			}
			found := false
			for _, lit := range singleQuotedLiterals(tc.script) {
				if lit == hostile {
					found = true
				}
			}
			if !found {
				t.Fatalf("value did not round-trip as a single literal: %s", tc.script)
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
			var script string
			got, ok, cause := diskPercent(context.Background(), fakePS(tc.out, tc.err, &script), "C:")
			if got != tc.want || ok != tc.wantOK || cause != tc.wantCause {
				t.Fatalf("diskPercent = (%v, %v, %q), want (%v, %v, %q)", got, ok, cause, tc.want, tc.wantOK, tc.wantCause)
			}
			if !strings.HasPrefix(script, "$mount='C:';") || !strings.Contains(script, "Win32_LogicalDisk") {
				t.Fatalf("unexpected disk script: %s", script)
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
			var script string
			got, ok, cause := serviceState(context.Background(), fakePS(tc.out, tc.err, &script), "Spooler")
			if got != tc.want || ok != tc.wantOK || cause != tc.wantCause {
				t.Fatalf("serviceState = (%q, %v, %q), want (%q, %v, %q)", got, ok, cause, tc.want, tc.wantOK, tc.wantCause)
			}
			if !strings.HasPrefix(script, "$s=Get-Service -Name 'Spooler' ") {
				t.Fatalf("unexpected service script: %s", script)
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
			var script string
			got, ok, cause := rebootPending(context.Background(), fakePS(tc.out, tc.err, &script))
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
