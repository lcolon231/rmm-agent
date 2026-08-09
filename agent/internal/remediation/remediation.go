// SPDX-License-Identifier: AGPL-3.0-only
// Package remediation implements the bounded typed file and registry operations
// introduced by issue #59. Platform code must enforce policy independently of
// the server: a signed request is authentic, but is never trusted to be safe.
package remediation

import (
	"context"
	"encoding/json"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

// Execute runs one typed remediation command. Results are JSON so the server
// and dashboard can present digest, size, type, and rollback evidence without
// parsing free-form shell output.
func Execute(ctx context.Context, commandID, kind string, payload json.RawMessage) executor.Result {
	evidence, err := platformExecute(ctx, commandID, kind, payload)
	if err != nil {
		return executor.Result{ExitCode: -1, Stderr: "controlled remediation failed: " + err.Error()}
	}
	encoded, err := json.Marshal(evidence)
	if err != nil {
		return executor.Result{ExitCode: -1, Stderr: "controlled remediation failed: encode evidence"}
	}
	return executor.Result{
		ExitCode:         0,
		Stdout:           string(encoded),
		StdoutTotalBytes: int64(len(encoded)),
	}
}
