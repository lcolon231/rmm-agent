// Package protocol contains wire-contract constants shared by the agent's
// HTTP client and command verifier.
package protocol

const CommandEnvelopeV1 = "command-v1"

// SupportedCommandEnvelopeVersions returns a fresh slice so callers cannot
// mutate process-global negotiation state.
func SupportedCommandEnvelopeVersions() []string {
	return []string{CommandEnvelopeV1}
}
