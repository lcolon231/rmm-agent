//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatlaunch

func ForSession(_ uint32) (*Target, error) { return nil, ErrUnsupported }
func openConsole(_ string) error           { return ErrUnsupported }
