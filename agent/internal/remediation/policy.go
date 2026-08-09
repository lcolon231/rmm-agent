// SPDX-License-Identifier: AGPL-3.0-only
package remediation

import (
	"fmt"
	"strings"
)

// validateManagedWindowsPath is intentionally platform-independent so the
// lexical policy receives ordinary CI coverage even when tests run on Linux.
// Windows adds reparse-point checks before touching the filesystem.
func validateManagedWindowsPath(raw string) (string, error) {
	path := strings.ReplaceAll(strings.TrimSpace(raw), "/", `\`)
	if len(path) < 4 || len(path) > 260 || strings.ContainsRune(path, 0) ||
		strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `\?\`) ||
		strings.HasPrefix(path, `\.\`) || path[1] != ':' || path[2] != '\\' ||
		!((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) {
		return "", fmt.Errorf("path is not a supported absolute drive path")
	}
	parts := strings.Split(path[3:], `\`)
	cleanParts := make([]string, 0, len(parts))
	reserved := map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}
	for index := 1; index <= 9; index++ {
		reserved[fmt.Sprintf("COM%d", index)] = true
		reserved[fmt.Sprintf("LPT%d", index)] = true
	}
	for _, part := range parts {
		if part == "" || part == "." {
			return "", fmt.Errorf("path contains an empty or ambiguous segment")
		}
		if part == ".." || strings.Contains(part, ":") || strings.ContainsAny(part, "\x00\r\n") {
			return "", fmt.Errorf("path contains traversal, a device name, or an alternate data stream")
		}
		if strings.TrimRight(part, " .") != part || reserved[strings.ToUpper(strings.SplitN(part, ".", 2)[0])] {
			return "", fmt.Errorf("path contains an ambiguous or reserved device segment")
		}
		cleanParts = append(cleanParts, part)
	}
	if len(cleanParts) == 0 {
		return "", fmt.Errorf("path does not name a managed resource")
	}
	normalized := strings.ToUpper(path[:1]) + `:\` + strings.Join(cleanParts, `\`)
	folded := strings.ToLower(strings.TrimRight(normalized, `\`))
	roots := []string{`c:\programdata\nodelink\managed`, `c:\windows\temp\nodelink`}
	for _, root := range roots {
		if folded == root || strings.HasPrefix(folded, root+`\`) {
			return normalized, nil
		}
	}
	return "", fmt.Errorf("path is outside the managed transfer roots")
}
