// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"reflect"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
	"github.com/lcolon231/rmm/agent/internal/pwsh/pwshtest"
)

func TestRunJSON(t *testing.T) {
	cases := []struct {
		name    string
		reply   func(pwsh.Script) (pwsh.Result, error)
		want    []map[string]any
		wantErr bool
	}{
		{"array", pwshtest.Stdout(`[{"Model":"A"},{"Model":"B"}]`), []map[string]any{{"Model": "A"}, {"Model": "B"}}, false},
		// Windows PowerShell 5.1 collapses a one-element array to a bare object;
		// misreading it would report a one-disk machine as having no disks.
		{"single object", pwshtest.Stdout(`{"Model":"A"}`), []map[string]any{{"Model": "A"}}, false},
		{"empty", pwshtest.Stdout(""), nil, false},
		{"stderr warning does not corrupt stdout", pwshtest.Exit(`{"Model":"A"}`, "WARNING: slow", 0), []map[string]any{{"Model": "A"}}, false},
		{"malformed", pwshtest.Stdout(`{"Model":`), nil, true},
		{"exit failure", pwshtest.Exit(`{"Model":"A"}`, "denied", 1), nil, true},
		{"timeout", pwshtest.Fail(pwsh.ErrTimeout), nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &pwshtest.Fake{Reply: tc.reply}
			got, err := runJSON(context.Background(), fake.Run, "Get-Thing")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rows = %#v, want %#v", got, tc.want)
			}
			want := []pwsh.Script{{Body: "Get-Thing", Timeout: sectionTimeout}}
			if calls := fake.Calls(); !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls = %+v, want %+v", calls, want)
			}
		})
	}
}
