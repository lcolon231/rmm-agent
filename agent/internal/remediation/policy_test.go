// SPDX-License-Identifier: AGPL-3.0-only
package remediation

import "testing"

func TestValidateManagedWindowsPath(t *testing.T) {
	valid := []string{
		`C:\ProgramData\NodeLink\Managed\patch.bin`,
		`c:/windows/temp/nodelink/vendor/fix.msi`,
	}
	for _, input := range valid {
		if _, err := validateManagedWindowsPath(input); err != nil {
			t.Errorf("valid path %q rejected: %v", input, err)
		}
	}
	invalid := []string{
		`C:\ProgramData\NodeLink\Managed\..\secret.txt`,
		`\\server\share\payload.exe`,
		`\\?\C:\ProgramData\NodeLink\Managed\payload.exe`,
		`\\.\PhysicalDrive0`,
		`C:\ProgramData\NodeLink\Managed\payload.exe:stream`,
		`C:\ProgramData\NodeLink\Managed\CON`,
		`C:\ProgramData\NodeLink\Managed\LPT1.txt`,
		`C:\ProgramData\NodeLink\Managed\payload. `,
		`C:\Windows\System32\drivers\etc\hosts`,
		`relative\payload.exe`,
	}
	for _, input := range invalid {
		if _, err := validateManagedWindowsPath(input); err == nil {
			t.Errorf("unsafe path %q accepted", input)
		}
	}
}
