// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import "fmt"

// serviceName duplicates the installed Windows service name rather than
// importing the service package, which depends on this one.
const serviceName = "NodeLinkAgent"

// restartCommand returns the helper that restarts the Windows service. The
// restart cannot be performed inline: this process *is* the service, so
// stopping it would kill the caller before it could start anything. A detached
// cmd.exe does the stop/start after a short delay, which lets the command
// result reach the server first. The service also has SCM failure actions
// configured, so even a helper that never runs leaves the service restarting
// on its own.
//
// The argument vector is fixed: no operator input reaches this command.
func restartCommand() (string, []string) {
	script := fmt.Sprintf(
		"ping -n 6 127.0.0.1 >NUL & sc stop %s >NUL & ping -n 4 127.0.0.1 >NUL & sc start %s >NUL",
		serviceName, serviceName,
	)
	return "cmd.exe", []string{"/c", script}
}
