// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"reflect"
	"testing"
)

type parseRow struct {
	Name string `json:"Name"`
	ID   int    `json:"Id"`
}

func TestUnmarshalMaybeArray(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    []parseRow
		wantErr bool
	}{
		{"single object", `{"Name":"a","Id":1}`, []parseRow{{"a", 1}}, false},
		{"single object padded", "  \r\n{\"Name\":\"a\",\"Id\":1}\r\n", []parseRow{{"a", 1}}, false},
		{"array", `[{"Name":"a","Id":1},{"Name":"b","Id":2}]`, []parseRow{{"a", 1}, {"b", 2}}, false},
		{"array padded", "\n [{\"Name\":\"a\",\"Id\":1}] \n", []parseRow{{"a", 1}}, false},
		{"empty array", `[]`, []parseRow{}, false},
		{"empty", ``, nil, false},
		{"whitespace", " \r\n\t ", nil, false},
		// NOTE: a bare "null" is wrapped as "[null]" and yields one zero-value row
		// rather than zero rows. Pinned as-is; PowerShell emits no output (not "null") for no rows.
		{"null", `null`, []parseRow{{}}, false},
		{"garbage", `not json`, nil, true},
		{"truncated array", `[{"Name":"a"`, nil, true},
		{"truncated object", `{"Name":"a"`, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []parseRow
			err := unmarshalMaybeArray([]byte(tt.in), &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %#v want %#v", got, tt.want)
			}
		})
	}
}

func TestFirstLine(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty", "", "service control failed"},
		{"single", "boom", "boom"},
		{"lf", "first\nsecond", "first"},
		{"crlf", "first  \r\nsecond", "first"},
		{"leading newline", "\nsecond", ""},
		{"whitespace only no newline", "  ", "  "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstLine(tt.in); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestLastLine(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"only newlines", "\r\n\n", ""},
		{"single", "Running", "Running"},
		{"multi", "warning\r\nRunning", "Running"},
		{"trailing newline", "a\nb\r\n", "b"},
		{"blank lines between", "a\n\n\nb ", "b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := lastLine(tt.in); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}
