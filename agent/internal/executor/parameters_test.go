// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRenderParameterizedPowerShellUsesTypedLiterals(t *testing.T) {
	hostile := "a'; Write-Output PWNED; #'\n$(touch /tmp/pwned)"
	rendered, err := RenderParameterizedScript(KindPowerShell, "Write-Output $NL_PARAM_Name", []ParameterValue{
		{Key: "Name", Kind: ParameterString, Value: hostile},
		{Key: "Enabled", Kind: ParameterBoolean, Value: true},
		{Key: "Count", Kind: ParameterNumber, Value: json.Number("2.5")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, "$NL_PARAM_Name = 'a''; Write-Output PWNED; #''") {
		t.Fatalf("string was not single-quoted safely: %s", rendered)
	}
	if !strings.Contains(rendered, "$NL_PARAM_Enabled = $true") || !strings.Contains(rendered, "$NL_PARAM_Count = 2.5") {
		t.Fatalf("typed literals missing: %s", rendered)
	}
	if !strings.HasSuffix(rendered, "Write-Output $NL_PARAM_Name") {
		t.Fatalf("script source was changed: %s", rendered)
	}
}

func TestRenderParameterizedShellQuotesAndExports(t *testing.T) {
	rendered, err := RenderParameterizedScript(KindShell, `printf "%s" "$NL_PARAM_Name"`, []ParameterValue{
		{Key: "Name", Kind: ParameterString, Value: "a'; rm -rf / #"},
		{Key: "Enabled", Kind: ParameterBoolean, Value: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, `NL_PARAM_Name='a'"'"'; rm -rf / #'`) {
		t.Fatalf("shell literal was not quoted safely: %s", rendered)
	}
	if !strings.Contains(rendered, "export NL_PARAM_Name") || !strings.Contains(rendered, "NL_PARAM_Enabled='false'") {
		t.Fatalf("parameter exports missing: %s", rendered)
	}
}

func TestRenderParameterizedScriptRejectsInvalidContracts(t *testing.T) {
	tests := [][]ParameterValue{
		{{Key: "bad-key", Kind: ParameterString, Value: "x"}},
		{{Key: "Name", Kind: ParameterString, Value: "x"}, {Key: "name", Kind: ParameterString, Value: "y"}},
		{{Key: "Count", Kind: ParameterNumber, Value: "1"}},
		{{Key: "Future", Kind: "future", Value: "x"}},
	}
	for _, parameters := range tests {
		if _, err := RenderParameterizedScript(KindShell, "true", parameters); err == nil {
			t.Fatalf("expected invalid parameters to fail: %#v", parameters)
		}
	}
	if _, err := RenderParameterizedScript(KindInventory, "true", []ParameterValue{{Key: "Name", Kind: ParameterString, Value: "x"}}); err == nil {
		t.Fatal("inventory parameter binding must be unsupported")
	}
}

func TestRedactParameterSecretsIsLongestFirst(t *testing.T) {
	parameters := []ParameterValue{
		{Key: "Token", Kind: ParameterSecret, Value: "secret-token"},
		{Key: "Short", Kind: ParameterSecret, Value: "secret"},
		{Key: "Visible", Kind: ParameterString, Value: "safe"},
	}
	got := RedactParameterSecrets("secret-token secret safe", parameters)
	if got != "[redacted] [redacted] safe" {
		t.Fatalf("unexpected redaction: %q", got)
	}
}
