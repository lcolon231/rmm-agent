//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// serviceName duplicates the installed Windows service name rather than
// importing the service package, which depends on this one.
const serviceName = "NodeLinkAgent"

// platformVerifyAuthenticode returns whether the staged artifact carries a Valid
// Authenticode signature and the signer certificate's SHA-1 thumbprint.
func platformVerifyAuthenticode(ctx context.Context, path string) (bool, string, error) {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	script := "$s = Get-AuthenticodeSignature -LiteralPath $env:NL_UPDATE_PATH; " +
		"if ($s.SignerCertificate) { Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Thumbprint) } " +
		"else { Write-Output ($s.Status.ToString() + '|') }"
	cmd := exec.CommandContext(bounded, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "NL_UPDATE_PATH="+path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, "", fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	fields := strings.SplitN(strings.TrimSpace(string(out)), "|", 2)
	status := ""
	thumbprint := ""
	if len(fields) > 0 {
		status = strings.TrimSpace(fields[0])
	}
	if len(fields) > 1 {
		thumbprint = strings.TrimSpace(fields[1])
	}
	return strings.EqualFold(status, "Valid"), thumbprint, nil
}

// platformRestartService asks the service control manager to restart the agent.
// The restart cannot be performed inline: this process *is* the service, so
// stopping it would kill the caller before it could start anything. A detached
// helper does the stop/start after a short delay, which lets the command result
// reach the server first. The service also has SCM failure actions configured,
// so even a helper that never runs leaves the service restarting on its own.
func platformRestartService(ctx context.Context) error {
	if _, err := exec.LookPath("cmd.exe"); err != nil {
		return fmt.Errorf("cmd.exe is unavailable: %w", err)
	}
	// Bounded, fixed argument vector: no operator input reaches this command.
	script := fmt.Sprintf(
		"ping -n 6 127.0.0.1 >NUL & sc stop %s >NUL & ping -n 4 127.0.0.1 >NUL & sc start %s >NUL",
		serviceName, serviceName,
	)
	cmd := exec.Command("cmd.exe", "/c", script)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("request service restart: %w", err)
	}
	// Detach: the helper must outlive this process.
	return cmd.Process.Release()
}

// replaceRunningBinary installs src at dest. Windows refuses to overwrite the
// image of a running process but does permit renaming it, so the running image
// is displaced to a .old- name first and the new binary is renamed into the
// vacated path. A failure after the displacement puts the original back, so
// dest is never left missing.
func replaceRunningBinary(src, dest string) error {
	displaced := fmt.Sprintf("%s.old-%d", dest, time.Now().UTC().UnixNano())
	displacedExisting := true
	if err := os.Rename(dest, displaced); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("displace running binary: %w", err)
		}
		displacedExisting = false
	}
	if err := os.Rename(src, dest); err != nil {
		if displacedExisting {
			// Put the original back before reporting failure.
			_ = os.Rename(displaced, dest)
		}
		return fmt.Errorf("install new binary: %w", err)
	}
	if displacedExisting {
		// Best effort: the displaced image stays locked while the old process
		// runs, so it is removed on a later start instead.
		_ = os.Remove(displaced)
	}
	return nil
}

// pruneDisplacedImages removes .old- images left locked by a previous run. It
// is best effort and never fails an update.
func pruneDisplacedImages(exePath string) {
	matches, err := filepath.Glob(exePath + ".old-*")
	if err != nil {
		return
	}
	for _, path := range matches {
		_ = os.Remove(path)
	}
}
