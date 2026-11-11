// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"encoding/base64"
	"testing"
	"unicode/utf16"
)

// Expected values are independent of encodeUTF16LE: the "dir" vector is the
// example from the powershell.exe -EncodedCommand documentation, the rest were
// produced with Python's base64.b64encode(s.encode("utf-16-le")).
func TestEncodeUTF16LE(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"empty", "", ""},
		{"single ascii", "A", "QQA="},
		{"documented example", `dir "c:\program files" `, "ZABpAHIAIAAiAGMAOgBcAHAAcgBvAGcAcgBhAG0AIABmAGkAbABlAHMAIgAgAA=="},
		{"install prefix", "$InstallAll = $false; $TargetKBs = @('KB5034441');",
			"JABJAG4AcwB0AGEAbABsAEEAbABsACAAPQAgACQAZgBhAGwAcwBlADsAIAAkAFQAYQByAGcAZQB0AEsAQgBzACAAPQAgAEAAKAAnAEsAQgA1ADAAMwA0ADQANAAxACcAKQA7AA=="},
		{"latin-1 and BMP", "café €", "YwBhAGYA6QAgAKwg"},
		{"surrogate pair", "\U0001F600", "PdgA3g=="},
		{"CRLF preserved", "a\r\nb", "YQANAAoAYgA="},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := encodeUTF16LE(tc.in); got != tc.want {
				t.Fatalf("encodeUTF16LE(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// The whole install script must survive the encoding unchanged, since that is
// the exact payload handed to -EncodedCommand.
func TestEncodeUTF16LERoundTripsInstallScript(t *testing.T) {
	raw, err := base64.StdEncoding.DecodeString(encodeUTF16LE(psInstallScriptForEncodingTest))
	if err != nil {
		t.Fatalf("decode base64: %v", err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("odd byte length %d", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for i := range units {
		units[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	if got := string(utf16.Decode(units)); got != psInstallScriptForEncodingTest {
		t.Fatalf("round trip changed the script")
	}
}

const psInstallScriptForEncodingTest = "$InstallAll = $true; $TargetKBs = @(); $TargetUpdateIDs = @();\n" +
	"$result = [ordered]@{ status = 'success' }\n$result | ConvertTo-Json -Compress\n# naïve — ✓ \U0001F600\n"
