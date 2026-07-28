//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func readSecret() (string, error) {
	handle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return "", fmt.Errorf("open terminal input: %w", err)
	}
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return "", fmt.Errorf("interactive input is not a console; use --token-stdin, --token-file, or --token-env")
	}
	if err := windows.SetConsoleMode(handle, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", fmt.Errorf("disable terminal echo: %w", err)
	}
	defer windows.SetConsoleMode(handle, mode) // best effort restore
	value, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("read hidden token: %w", err)
	}
	return value, nil
}
