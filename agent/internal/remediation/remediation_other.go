//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package remediation

import (
	"context"
	"encoding/json"
	"fmt"
)

func platformExecute(context.Context, string, string, json.RawMessage) (map[string]any, error) {
	return nil, fmt.Errorf("file transfer and registry operations are supported only on Windows")
}
