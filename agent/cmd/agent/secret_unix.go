//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func readSecret() (string, error) {
	disable := exec.Command("stty", "-echo")
	disable.Stdin = os.Stdin
	if err := disable.Run(); err != nil {
		return "", fmt.Errorf("cannot disable terminal echo; use --token-stdin, --token-file, or --token-env")
	}
	defer func() {
		restore := exec.Command("stty", "echo")
		restore.Stdin = os.Stdin
		_ = restore.Run()
	}()
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("read hidden token: %w", err)
	}
	return value, nil
}
