// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"encoding/json"
	"strings"
)

// unmarshalMaybeArray decodes ConvertTo-Json output, which emits a bare object
// (not an array) when there is exactly one row and nothing for zero rows.
func unmarshalMaybeArray(data []byte, target any) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal([]byte(trimmed), target)
	}
	// Wrap a single object in an array so the caller always sees a slice.
	return json.Unmarshal([]byte("["+trimmed+"]"), target)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "service control failed"
	}
	return s
}

func lastLine(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == '\r' || r == '\n' })
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(fields[len(fields)-1])
}
