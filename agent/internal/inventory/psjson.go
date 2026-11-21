// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"encoding/json"
	"time"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// Per-section timeout. Inventory runs on the heartbeat goroutine, so a wedged
// CIM provider must not be able to stall check-in; the section it belongs to
// is reported unavailable and the rest still collect.
const sectionTimeout = 30 * time.Second

// runJSON runs a PowerShell snippet and decodes its JSON stdout into rows.
//
// Windows PowerShell 5.1 collapses a single-element array to a bare object, so
// the result is decoded as an array first and retried as one object. Getting
// this wrong would silently report a one-disk machine as having no disks.
//
// It lives in an untagged file so every CI job covers the decoding; the
// Windows build binds run to pwsh.Exec.
func runJSON(ctx context.Context, run pwsh.Runner, script string) ([]map[string]any, error) {
	res, err := run(ctx, pwsh.Script{Body: script, Timeout: sectionTimeout})
	if err != nil {
		return nil, err
	}
	out := res.Stdout
	if len(out) == 0 {
		return nil, nil
	}

	var rows []map[string]any
	if err := json.Unmarshal(out, &rows); err == nil {
		return rows, nil
	}
	var single map[string]any
	if err := json.Unmarshal(out, &single); err != nil {
		return nil, err
	}
	return []map[string]any{single}, nil
}
