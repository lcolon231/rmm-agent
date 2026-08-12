//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package executor

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Windows end-to-end evidence for issue #61: a real contained PowerShell
// process accepts input and exposes stdout before the session completes.
func TestRunInteractivePowerShellStreamsOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	input := make(chan []byte, 2)
	output := make(chan InteractiveChunk, 8)
	done := make(chan error, 1)
	go func() { done <- RunInteractive(ctx, input, output) }()
	input <- []byte("Write-Output 'NODELINK-SHELL-E2E'\r\n")
	input <- []byte("exit\r\n")
	close(input)

	var stdout strings.Builder
	for {
		select {
		case chunk := <-output:
			if chunk.Stream == "stdout" {
				stdout.Write(chunk.Data)
			}
			if strings.Contains(stdout.String(), "NODELINK-SHELL-E2E") {
				return
			}
		case err := <-done:
			if err != nil {
				t.Fatalf("interactive PowerShell: %v", err)
			}
			if !strings.Contains(stdout.String(), "NODELINK-SHELL-E2E") {
				t.Fatalf("stdout = %q, want marker", stdout.String())
			}
			return
		case <-ctx.Done():
			t.Fatalf("interactive PowerShell timed out; stdout=%q", stdout.String())
		}
	}
}
