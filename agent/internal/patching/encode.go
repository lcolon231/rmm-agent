// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"encoding/base64"
	"unicode/utf16"
)

// encodeUTF16LE encodes s for powershell.exe -EncodedCommand, which takes the
// base64 of the script's UTF-16LE bytes. It lives outside the Windows-only
// install file so its table test runs on every platform's CI job.
func encodeUTF16LE(s string) string {
	encoded := utf16.Encode([]rune(s))
	buf := make([]byte, len(encoded)*2)
	for i, u := range encoded {
		buf[i*2] = byte(u)
		buf[i*2+1] = byte(u >> 8)
	}
	return base64.StdEncoding.EncodeToString(buf)
}
