//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package chattray

func run() error { return ErrUnsupported }
