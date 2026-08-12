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
	// PackageManagementCapabilityV1 names Winget-based package discovery/install/
	// upgrade support (issue #55). Always advertised on Windows builds; the server
	// fails closed and never dispatches scan_packages/install_packages to an agent
	// that has not advertised it.
	PackageManagementCapabilityV1 = "package-management-v1"
	// ChocolateyProviderCapabilityV1 names the optional Chocolatey provider. It is
	// advertised only when the operator explicitly enables Chocolatey in the agent
	// config, so a Chocolatey install can never be dispatched to an endpoint that
	// has not opted in.
	ChocolateyProviderCapabilityV1 = "chocolatey-provider-v1"
	// SoftwareDeploymentCapabilityV1 names MSI/EXE software deployment support
	// (issue #56): authenticated HTTPS download, digest/signature verification,
	// bounded install, and reboot policy. The server fails closed and never
	// dispatches deploy_software to an agent that has not advertised it.
	SoftwareDeploymentCapabilityV1 = "software-deployment-v1"
)

// SupportedCommandEnvelopeVersions returns a fresh slice so callers cannot
// mutate process-global negotiation state.
func SupportedCommandEnvelopeVersions() []string {
	return []string{CommandEnvelopeV3, CommandEnvelopeV2}
}

// SupportedCapabilities returns the optional feature capabilities this agent
// advertises with Chocolatey disabled. A fresh slice is returned so callers
// cannot mutate process-global negotiation state.
func SupportedCapabilities() []string {
	return SupportedCapabilitiesWith(false)
}

// SupportedCapabilitiesWith returns the advertised capabilities, including the
// opt-in Chocolatey provider only when chocolateyEnabled is true. A fresh slice
// is returned so callers cannot mutate process-global negotiation state.
func SupportedCapabilitiesWith(chocolateyEnabled bool) []string {
	caps := []string{
		ShellSessionCapabilityV1,
		FileTransferCapabilityV1,
		RegistryOperationsCapabilityV1,
		PowerOperationsCapabilityV1,
		EventLogQueryCapabilityV1,
		PatchRebootCapabilityV1,
		PackageManagementCapabilityV1,
		SoftwareDeploymentCapabilityV1,
	}
	if chocolateyEnabled {
		caps = append(caps, ChocolateyProviderCapabilityV1)
	}
	return caps
}
