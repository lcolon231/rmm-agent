// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bytes"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/chatpipe"
)

func TestReportUserErrorPrintsWithConsole(t *testing.T) {
	var stderr bytes.Buffer
	shown := ""
	reportUserError(&stderr, true, func(s string) { shown = s }, chatpipe.ErrUnavailable)
	if got := stderr.String(); got != chatpipe.ErrUnavailable.Error()+"\n" {
		t.Fatalf("stderr = %q", got)
	}
	if shown != "" {
		t.Fatalf("dialog shown with a console: %q", shown)
	}
}

func TestReportUserErrorShowsDialogWithoutConsole(t *testing.T) {
	for _, err := range []error{chatpipe.ErrUnavailable, chatpipe.ErrRefused} {
		var stderr bytes.Buffer
		shown := ""
		reportUserError(&stderr, false, func(s string) { shown = s }, err)
		if shown != err.Error() {
			t.Fatalf("dialog = %q, want %q", shown, err.Error())
		}
		if stderr.Len() != 0 {
			t.Fatalf("stderr written without a console: %q", stderr.String())
		}
	}
}
