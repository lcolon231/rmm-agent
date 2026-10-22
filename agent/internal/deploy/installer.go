// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/authenticode"
)

// The shell-outs behind the Windows platform functions. They live in an
// untagged file so the argv and the output handling are covered on every CI
// job; deploy_windows.go only wires them to real processes.

// pathEnvVar carries the installer path to PowerShell outside the script text.
const pathEnvVar = "NL_DEPLOY_PATH"

// processRunner runs a program to completion and returns its exit code. A
// non-zero exit is an outcome, not an error; err is reserved for a process that
// could not be run at all.
type processRunner func(ctx context.Context, name string, args ...string) (int, error)

func execProcess(ctx context.Context, name string, args ...string) (int, error) {
	err := exec.CommandContext(ctx, name, args...).Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

// installerCommand returns the process that installs path. MSI runs through
// msiexec with /qn /norestart so the installer is non-interactive and never
// reboots on its own — reboot is managed by the signed reboot policy. EXE
// installers run directly with operator args (which must carry their own
// silent switch).
func installerCommand(installerType, path string, args []string) (string, []string, error) {
	switch installerType {
	case InstallerMSI:
		return "msiexec.exe", append([]string{"/i", path, "/qn", "/norestart"}, args...), nil
	case InstallerEXE:
		return path, append([]string(nil), args...), nil
	default:
		return "", nil, fmt.Errorf("unsupported installer type %q", installerType)
	}
}

// runInstallerWith runs the installer under a bounded timeout and returns its
// process exit code.
func runInstallerWith(ctx context.Context, run processRunner, installerType, path string, args []string, timeout time.Duration) (int, error) {
	name, argv, err := installerCommand(installerType, path, args)
	if err != nil {
		return -1, err
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	code, err := run(bounded, name, argv...)
	if bounded.Err() == context.DeadlineExceeded {
		return -1, fmt.Errorf("installer timed out after %s", timeout)
	}
	if err != nil {
		return -1, err
	}
	return code, nil
}

// productCodeScript reads an MSI's ProductCode through the WindowsInstaller COM
// object, taking the path from pathEnvVar.
const productCodeScript = "$i = New-Object -ComObject WindowsInstaller.Installer; " +
	"$db = $i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($env:" + pathEnvVar + ",0)); " +
	"$v = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@(\"SELECT Value FROM Property WHERE Property='ProductCode'\")); " +
	"$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null) | Out-Null; " +
	"$r = $v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null); " +
	"if ($r) { Write-Output $r.GetType().InvokeMember('StringData','GetProperty',$null,$r,@(1)) }"

// readProductCodeWith returns the MSI's ProductCode so an operator has the code
// needed to uninstall (`msiexec /x`). A read failure yields an empty string
// rather than failing the deployment.
func readProductCodeWith(ctx context.Context, run authenticode.Runner, path string) string {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := run(bounded, []string{pathEnvVar + "=" + path},
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", productCodeScript)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
