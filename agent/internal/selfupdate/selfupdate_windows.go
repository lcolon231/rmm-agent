//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/lcolon231/rmm/agent/internal/authenticode"
)

// Process seams, swapped by tests so no PowerShell or sc.exe ever starts.
var (
	runPowerShell authenticode.Runner = authenticode.Exec
	lookPath                          = exec.LookPath
	startDetached                     = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		if err := cmd.Start(); err != nil {
			return err
		}
		// Detach: the helper must outlive this process.
		return cmd.Process.Release()
	}
)

// platformVerifyAuthenticode returns whether the staged artifact carries a Valid
// Authenticode signature and the signer certificate's SHA-1 thumbprint.
func platformVerifyAuthenticode(ctx context.Context, path string) (bool, string, error) {
	return authenticode.Verify(ctx, runPowerShell, "NL_UPDATE_PATH", path)
}

// platformRestartService asks the service control manager to restart the agent
// through the detached helper described at restartCommand.
func platformRestartService(_ context.Context) error {
	name, args := restartCommand()
	if _, err := lookPath(name); err != nil {
		return fmt.Errorf("%s is unavailable: %w", name, err)
	}
	if err := startDetached(name, args...); err != nil {
		return fmt.Errorf("request service restart: %w", err)
	}
	return nil
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
	// Left in place even though displacedExisting: the running process still
	// holds this image open (with FILE_SHARE_DELETE, the way the loader does),
	// so an immediate os.Remove would unlink it right away instead of leaving it
	// for the process to keep using. It is pruned on a later start instead.
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
