// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"io"
)

// reportUserError surfaces an error from a user-facing verb (chat, tray). The
// console build prints it to stderr as before; the GUI build, which has no
// console, shows a dialog instead so the failure is never silent (issue #322).
func reportUserError(stderr io.Writer, console bool, show func(string), err error) {
	if console {
		fmt.Fprintln(stderr, err)
		return
	}
	show(err.Error())
}
