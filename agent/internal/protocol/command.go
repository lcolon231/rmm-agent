// SPDX-License-Identifier: AGPL-3.0-only
// Package protocol contains wire-contract constants shared by the agent's
// HTTP client and command verifier.
package protocol

const (
	CommandEnvelopeV1 = "command-v1"
	CommandEnvelopeV2 = "command-v2"
	CommandEnvelopeV3 = "command-v3"
	CommandSchemaV1   = 1

	// ShellSessionCapabilityV1 names interactive shell session support (issue
	// #61). The agent advertises it so the server can offer the feature; an
	// agent that does not advertise it makes the server fail closed as
	// "unsupported". Phase 1 advertises the capability only — the streaming
	// loop is added in a later phase.
	ShellSessionCapabilityV1       = "shell-session-v1"
	FileTransferCapabilityV1       = "file-transfer-v1"
	RegistryOperationsCapabilityV1 = "registry-operations-v1"
	PowerOperationsCapabilityV1    = "power-operations-v1"
	EventLogQueryCapabilityV1      = "event-log-query-v1"
	PatchRebootCapabilityV1        = "patch-reboot-v1"
)

// SupportedCommandEnvelopeVersions returns a fresh slice so callers cannot
// mutate process-global negotiation state.
func SupportedCommandEnvelopeVersions() []string {
	return []string{CommandEnvelopeV3, CommandEnvelopeV2}
}

// SupportedCapabilities returns the optional feature capabilities this agent
// advertises. A fresh slice is returned so callers cannot mutate process-global
// negotiation state.
func SupportedCapabilities() []string {
	return []string{
		ShellSessionCapabilityV1,
		FileTransferCapabilityV1,
		RegistryOperationsCapabilityV1,
		PowerOperationsCapabilityV1,
		EventLogQueryCapabilityV1,
		PatchRebootCapabilityV1,
	}
}
