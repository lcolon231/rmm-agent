// SPDX-License-Identifier: AGPL-3.0-only

// Package authenticode checks a downloaded binary's Authenticode signature by
// asking PowerShell's Get-AuthenticodeSignature for the status and the signer
// thumbprint. The deploy and self-update paths both gate execution on it.
//
// The PowerShell run goes through a pwsh.Runner so the script and the parsing
// of its output are testable on every platform; only the Windows callers wire
// the real pwsh.Exec.
package authenticode

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// Timeout bounds one verification.
const Timeout = 60 * time.Second

// Script returns the PowerShell run that verifies path, passed in the
// environment variable envVar. The path travels in the environment, never in
// the script text, so a hostile file name cannot change what PowerShell runs.
func Script(envVar, path string) pwsh.Script {
	body := "$s = Get-AuthenticodeSignature -LiteralPath $env:" + envVar + "; " +
		"if ($s.SignerCertificate) { Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Thumbprint) } " +
		"else { Write-Output ($s.Status.ToString() + '|') }"
	return pwsh.Script{Body: body, Env: map[string]string{envVar: path}, Timeout: Timeout}
}

// Parse reads the "Status|Thumbprint" line Script prints. Only a status of
// Valid counts as signed; NotSigned, HashMismatch, UnknownError and anything
// unrecognised do not.
func Parse(out []byte) (valid bool, thumbprint string) {
	fields := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	status := strings.TrimSpace(fields[0])
	if len(fields) > 1 {
		thumbprint = strings.TrimSpace(fields[1])
	}
	return strings.EqualFold(status, "Valid"), thumbprint
}

// Verify reports whether path carries a Valid Authenticode signature and the
// signer certificate's SHA-1 thumbprint. envVar names the variable that carries
// the path to PowerShell. A failed run is an error carrying what it printed.
func Verify(ctx context.Context, run pwsh.Runner, envVar, path string) (bool, string, error) {
	res, err := run(ctx, Script(envVar, path))
	if err != nil {
		detail := strings.TrimSpace(strings.TrimSpace(string(res.Stderr)) + " " + strings.TrimSpace(string(res.Stdout)))
		return false, "", fmt.Errorf("%w: %s", err, detail)
	}
	valid, thumbprint := Parse(res.Stdout)
	return valid, thumbprint, nil
}
