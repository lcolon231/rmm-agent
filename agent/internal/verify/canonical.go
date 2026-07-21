// SPDX-License-Identifier: AGPL-3.0-only
package verify

import (
	"bytes"
	"encoding/json"
)

// marshalCanonical produces JSON that matches Python's
// json.dumps(obj, sort_keys=True, separators=(",", ":")).
//
// Two things Go's default json.Marshal gets wrong for our purposes:
//  1. It HTML-escapes <, >, and & (Python does not). We disable that.
//  2. Marshal already sorts map[string]any keys alphabetically and omits
//     insignificant whitespace, which matches Python here.
//
// json.Encoder.Encode appends a trailing newline, which we trim.
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
