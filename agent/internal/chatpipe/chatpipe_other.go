//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package chatpipe

import "context"

func Serve(_ context.Context, _ Handler) error { return ErrUnsupported }
func Request(_ context.Context) error          { return ErrUnsupported }
