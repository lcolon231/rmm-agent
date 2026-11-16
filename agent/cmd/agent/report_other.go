//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"fmt"
	"os"
)

// reportError writes err to stderr. Only Windows has a GUI-subsystem build
// that needs a dialog instead (see report_windows.go).
func reportError(err error) {
	fmt.Fprintln(os.Stderr, err)
}

// reportInfo writes a confirmation to stdout.
func reportInfo(msg string) {
	fmt.Println(msg)
}
