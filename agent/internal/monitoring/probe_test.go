// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"reflect"
	"testing"
)

func TestParseRebootSourcesReportsEachSourceIndependently(t *testing.T) {
	for _, testCase := range []struct {
		name string
		out  string
		want RebootSources
	}{
		{name: "none", out: "false false false 0"},
		{name: "servicing only", out: "true false false 0", want: RebootSources{ComponentBasedServicing: true}},
		{name: "update only", out: "false true false 0", want: RebootSources{WindowsUpdate: true}},
		{name: "rename only", out: "false false true 2", want: RebootSources{PendingFileRename: true, PendingFileRenameCount: 2}},
		{name: "all three", out: "true true true 7", want: RebootSources{
			ComponentBasedServicing: true, WindowsUpdate: true, PendingFileRename: true, PendingFileRenameCount: 7,
		}},
		{name: "extra whitespace", out: "true\tfalse  false\n0", want: RebootSources{ComponentBasedServicing: true}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := parseRebootSources(testCase.out)
			if !ok || got != testCase.want {
				t.Fatalf("parseRebootSources(%q) = %#v, %v", testCase.out, got, ok)
			}
			if got.Pending() != (got.ComponentBasedServicing || got.WindowsUpdate || got.PendingFileRename) {
				t.Fatalf("Pending() disagrees with the flags: %#v", got)
			}
		})
	}
}

// A failed count query must never cost us the source flags, which are what
// decides status.
func TestParseRebootSourcesTreatsTheCountAsBestEffort(t *testing.T) {
	for _, out := range []string{"false false true nan", "false false true -1"} {
		got, ok := parseRebootSources(out)
		if !ok || !got.PendingFileRename || got.PendingFileRenameCount != 0 {
			t.Fatalf("parseRebootSources(%q) = %#v, %v", out, got, ok)
		}
	}
}

func TestParseRebootSourcesRejectsMalformedOutput(t *testing.T) {
	for _, out := range []string{"", "true false false", "true false false 0 1", "yes no maybe 0"} {
		if got, ok := parseRebootSources(out); ok {
			t.Fatalf("parseRebootSources(%q) accepted %#v", out, got)
		}
	}
}

// PendingFileRenameOperations paths carry user names and installer temp paths,
// and a check result detail fans out over alert email and third-party webhooks.
// Keeping the probe's return type free of strings is what makes "paths never
// leave the endpoint" structural rather than a review promise.
func TestRebootSourcesCannotCarryPaths(t *testing.T) {
	sources := reflect.TypeOf(RebootSources{})
	for index := 0; index < sources.NumField(); index++ {
		field := sources.Field(index)
		switch kind := field.Type.Kind(); kind {
		case reflect.Bool, reflect.Int:
		default:
			t.Fatalf("RebootSources.%s is a %s; only flags and counts may be returned", field.Name, kind)
		}
	}
}
