// SPDX-License-Identifier: AGPL-3.0-only
package selfupdate

import (
	"reflect"
	"testing"
)

// TestRestartCommandIsFixed pins the exact helper argv: a restart must target
// the installed service and never interpolate caller-controlled text.
func TestRestartCommandIsFixed(t *testing.T) {
	name, args := restartCommand()
	want := []string{"/c", "ping -n 6 127.0.0.1 >NUL & sc stop NodeLinkAgent >NUL & ping -n 4 127.0.0.1 >NUL & sc start NodeLinkAgent >NUL"}
	if name != "cmd.exe" || !reflect.DeepEqual(args, want) {
		t.Fatalf("restartCommand() = %q %#v, want cmd.exe %#v", name, args, want)
	}
}
