// SPDX-License-Identifier: AGPL-3.0-only
// Package protocol contains wire-contract constants shared by the agent's
// HTTP client and command verifier.
package protocol

const (
	CommandEnvelopeV1 = "command-v1"
	CommandEnvelopeV2 = "command-v2"
	CommandEnvelopeV3 = "command-v3"
	CommandSchemaV1   = 1
)

// SupportedCommandEnvelopeVersions returns a fresh slice so callers cannot
// mutate process-global negotiation state.
func SupportedCommandEnvelopeVersions() []string {
	return []string{CommandEnvelopeV3, CommandEnvelopeV2}
}
