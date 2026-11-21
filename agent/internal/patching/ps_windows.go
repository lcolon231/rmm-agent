//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package patching

import "github.com/lcolon231/rmm/agent/internal/pwsh"

// runPS runs the Windows Update scan and install scripts; a var so tests can
// substitute a fake.
var runPS pwsh.Runner = pwsh.Exec
