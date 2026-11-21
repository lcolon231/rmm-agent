// SPDX-License-Identifier: AGPL-3.0-only
package pwsh

import (
	"reflect"
	"strings"
	"testing"
)

func TestArgsUseTheHardenedFlagSet(t *testing.T) {
	want := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"}
	if got := Args(Script{Body: "Get-Date"}); !reflect.DeepEqual(got, want) {
		t.Fatalf("Args = %q, want %q", got, want)
	}
}

func TestArgsEncodedCarriesUTF16LEBase64(t *testing.T) {
	got := Args(Script{Body: "é", Encoded: true})
	// "é" is U+00E9: UTF-16LE bytes E9 00, base64 "6QA=".
	want := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", "6QA="}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Args = %q, want %q", got, want)
	}
}

func TestStdinArgsReadTheScriptFromStandardInput(t *testing.T) {
	want := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"}
	if got := StdinArgs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("StdinArgs = %q, want %q", got, want)
	}
}

func TestEnvironDropsPSModulePathAndAppendsArgumentsSorted(t *testing.T) {
	base := []string{"PATH=C:\\Windows", "PSModulePath=C:\\pwsh7\\Modules", "psmodulepath=x", "PSModulePath=", "PSModulePathExtra=z", "USERNAME=bob"}
	got, err := Environ(base, map[string]string{"NL_B": "two", "NL_A": `it's "quoted"`})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PATH=C:\\Windows", "PSModulePathExtra=z", "USERNAME=bob", `NL_A=it's "quoted"`, "NL_B=two"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Environ = %q, want %q", got, want)
	}
}

func TestEnvironRejectsNamesThatCouldSmuggleAssignments(t *testing.T) {
	for _, name := range []string{"", "A=B", "1NL", "NL ARG", "NL-ARG", "PSModulePath"} {
		if _, err := Environ(nil, map[string]string{name: "v"}); err == nil {
			t.Fatalf("Environ accepted name %q", name)
		}
	}
	if _, err := Environ(nil, map[string]string{"NL_ARG": "a\x00b"}); err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("Environ accepted a NUL value: %v", err)
	}
}
