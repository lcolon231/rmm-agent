// SPDX-License-Identifier: AGPL-3.0-only

// Package authenticode checks a downloaded binary's Authenticode signature by
// asking PowerShell's Get-AuthenticodeSignature for the status and the signer
// thumbprint. The deploy and self-update paths both gate execution on it.
//
// The process launch is a Runner so the command line and the parsing of its
// output are testable on every platform; only the Windows callers wire the real
// Exec runner to powershell.exe.
package authenticode

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Timeout bounds one verification.
const Timeout = 60 * time.Second

// Runner runs name with args, adding env to the inherited environment, and
// returns the process's standard output. A failure to start or a non-zero exit
// is an error that carries whatever the process printed.
type Runner func(ctx context.Context, env []string, name string, args ...string) ([]byte, error)

// Exec is the Runner that starts a real process.
func Exec(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(childEnv(cmd.Environ()), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		detail := strings.TrimSpace(strings.TrimSpace(stderr.String()) + " " + strings.TrimSpace(string(out)))
		return out, fmt.Errorf("%w: %s", err, detail)
	}
	return out, nil
}

// childEnv drops an inherited PSModulePath. When the agent is started from
// PowerShell 7, that variable points at PowerShell 7's modules, and the Windows
// PowerShell child then cannot load Microsoft.PowerShell.Security, so every
// signature check would fail. Without it, powershell.exe rebuilds its default.
func childEnv(environ []string) []string {
	kept := make([]string, 0, len(environ))
	for _, kv := range environ {
		if len(kv) >= len("PSModulePath=") && strings.EqualFold(kv[:len("PSModulePath=")], "PSModulePath=") {
			continue
		}
		kept = append(kept, kv)
	}
	return kept
}

// Command returns the PowerShell invocation that verifies the file named by the
// environment variable envVar. The path travels in the environment, never in
// the script text, so a hostile file name cannot change what PowerShell runs.
func Command(envVar string) (string, []string) {
	script := "$s = Get-AuthenticodeSignature -LiteralPath $env:" + envVar + "; " +
		"if ($s.SignerCertificate) { Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Thumbprint) } " +
		"else { Write-Output ($s.Status.ToString() + '|') }"
	return "powershell.exe", []string{"-NoProfile", "-NonInteractive", "-Command", script}
}

// Parse reads the "Status|Thumbprint" line Command prints. Only a status of
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
// the path to PowerShell.
func Verify(ctx context.Context, run Runner, envVar, path string) (bool, string, error) {
	bounded, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	name, args := Command(envVar)
	out, err := run(bounded, []string{envVar + "=" + path}, name, args...)
	if err != nil {
		return false, "", err
	}
	valid, thumbprint := Parse(out)
	return valid, thumbprint, nil
}
