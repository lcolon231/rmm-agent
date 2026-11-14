//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package main

func hasConsole() bool { return true }

func showUserError(string) {}
