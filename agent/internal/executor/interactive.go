// SPDX-License-Identifier: AGPL-3.0-only
package executor

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

// InteractiveChunk is one bounded piece of process output.
type InteractiveChunk struct {
	Stream string
	Data   []byte
}

const interactiveChunkBytes = 8 * 1024

// RunInteractive starts one line-oriented shell. The platform runCommand
// implementation supplies the same process-tree containment used by signed
// commands. Input is never persisted by the executor and output is delivered
// incrementally with natural backpressure through the output channel.
func RunInteractive(ctx context.Context, input <-chan []byte, output chan<- InteractiveChunk) error {
	cmd := buildInteractiveCommand()
	if cmd == nil {
		return fmt.Errorf("interactive shell is unsupported")
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("open shell stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open shell stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("open shell stderr: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- runCommand(ctx, cmd) }()

	var readers sync.WaitGroup
	readers.Add(2)
	copyStream := func(name string, source io.Reader) {
		defer readers.Done()
		buffer := make([]byte, interactiveChunkBytes)
		for {
			n, readErr := source.Read(buffer)
			if n > 0 {
				chunk := append([]byte(nil), buffer[:n]...)
				select {
				case output <- InteractiveChunk{Stream: name, Data: chunk}:
				case <-ctx.Done():
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}
	go copyStream("stdout", stdout)
	go copyStream("stderr", stderr)

	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		defer stdin.Close()
		for {
			select {
			case data, ok := <-input:
				if !ok {
					return
				}
				if _, writeErr := stdin.Write(data); writeErr != nil {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	runErr := <-done
	readers.Wait()
	return runErr
}

func buildInteractiveCommand() *exec.Cmd {
	return interactiveCommand()
}
