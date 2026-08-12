//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package deploy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// platformRunInstaller runs the installer under a bounded timeout and returns
// its process exit code. MSI runs through msiexec with /qn /norestart so the
// installer is non-interactive and never reboots on its own — reboot is managed
// by the signed reboot policy. EXE installers run directly with operator args
// (which must carry their own silent switch).
func platformRunInstaller(ctx context.Context, installerType, path string, args []string, timeout time.Duration) (int, error) {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var cmd *exec.Cmd
	switch installerType {
	case InstallerMSI:
		full := append([]string{"/i", path, "/qn", "/norestart"}, args...)
		cmd = exec.CommandContext(bounded, "msiexec.exe", full...)
	case InstallerEXE:
		cmd = exec.CommandContext(bounded, path, args...)
	default:
		return -1, fmt.Errorf("unsupported installer type %q", installerType)
	}

	err := cmd.Run()
	if bounded.Err() == context.DeadlineExceeded {
		return -1, fmt.Errorf("installer timed out after %s", timeout)
	}
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		// A non-zero exit code is an outcome to map, not an execution failure.
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

// platformVerifyAuthenticode returns whether the file carries a Valid
// Authenticode signature and the signer certificate's SHA-1 thumbprint.
func platformVerifyAuthenticode(ctx context.Context, path string) (bool, string, error) {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	script := "$s = Get-AuthenticodeSignature -LiteralPath $env:NL_DEPLOY_PATH; " +
		"if ($s.SignerCertificate) { Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Thumbprint) } " +
		"else { Write-Output ($s.Status.ToString() + '|') }"
	cmd := exec.CommandContext(bounded, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "NL_DEPLOY_PATH="+path)
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

// platformReadProductCode reads an MSI's ProductCode via the WindowsInstaller COM
// object so an operator has the code needed to uninstall (`msiexec /x`). A read
// failure yields an empty string rather than failing the deployment.
func platformReadProductCode(ctx context.Context, path string) string {
	bounded, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	script := "$i = New-Object -ComObject WindowsInstaller.Installer; " +
		"$db = $i.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$i,@($env:NL_DEPLOY_PATH,0)); " +
		"$v = $db.GetType().InvokeMember('OpenView','InvokeMethod',$null,$db,@(\"SELECT Value FROM Property WHERE Property='ProductCode'\")); " +
		"$v.GetType().InvokeMember('Execute','InvokeMethod',$null,$v,$null) | Out-Null; " +
		"$r = $v.GetType().InvokeMember('Fetch','InvokeMethod',$null,$v,$null); " +
		"if ($r) { Write-Output $r.GetType().InvokeMember('StringData','GetProperty',$null,$r,@(1)) }"
	cmd := exec.CommandContext(bounded, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(cmd.Environ(), "NL_DEPLOY_PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
