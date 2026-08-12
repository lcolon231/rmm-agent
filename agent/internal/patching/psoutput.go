// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"bytes"
	"encoding/json"
)

// extractPSJSON returns the JSON document a PowerShell collector emitted on
// stdout, tolerating unrelated text around it.
//
// The collectors end with `ConvertTo-Json -Compress`, so the payload is always a
// single line. Anything else PowerShell writes to the success stream — most
// often a COM call whose return value was neither assigned nor suppressed, which
// the default formatter renders as a property table — lands on stdout too and
// makes a whole-buffer json.Unmarshal fail on the first character of that noise.
// Scanning from the end for the last line that is a valid JSON object keeps the
// result parseable in that case instead of discarding a completed install.
//
// The full stdout is returned unchanged when no such line exists, so the caller
// reports the original parse error against the original bytes.
func extractPSJSON(stdout []byte) []byte {
	lines := bytes.Split(stdout, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		if json.Valid(line) {
			return line
		}
	}
	return stdout
}
