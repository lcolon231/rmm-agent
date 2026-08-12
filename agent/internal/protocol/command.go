// SPDX-License-Identifier: AGPL-3.0-only
// Package protocol contains wire-contract constants shared by the agent's
// HTTP client and command verifier.
package protocol

import "runtime"

const (
	CommandEnvelopeV1 = "command-v1"
	CommandEnvelopeV2 = "command-v2"
	CommandEnvelopeV3 = "command-v3"
	CommandSchemaV1   = 1

	// V1 advertised lifecycle-only support and must not unlock a terminal.
	// V2 means the agent implements the bounded framed transport.
	ShellSessionCapabilityV1       = "shell-session-v1"
	ShellSessionCapabilityV2       = "shell-session-v2"
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
	// ServiceProcessCapabilityV1 names Windows service/process management (issue
	// #57): list services/processes and validated, protected-target-guarded
	// service control and process termination. The server fails closed and never
	// dispatches those kinds to an agent that has not advertised it.
	ServiceProcessCapabilityV1 = "service-process-v1"
	// AgentSelfUpdateCapabilityV1 names signed, staged agent self-update with
	// automatic rollback (issue #63). It is advertised only by Windows builds,
	// because committing an update needs the managed service restart the SCM
	// provides; the server fails closed and never dispatches agent_self_update
	// or agent_update_rollback to an agent that has not advertised it.
	AgentSelfUpdateCapabilityV1 = "agent-self-update-v1"
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
		ShellSessionCapabilityV2,
		FileTransferCapabilityV1,
		RegistryOperationsCapabilityV1,
		PowerOperationsCapabilityV1,
		EventLogQueryCapabilityV1,
		PatchRebootCapabilityV1,
		PackageManagementCapabilityV1,
		SoftwareDeploymentCapabilityV1,
		ServiceProcessCapabilityV1,
	}
	// Self-update commits through a Windows service restart, so only Windows
	// builds advertise it. Elsewhere the server keeps failing closed.
	if runtime.GOOS == "windows" {
		caps = append(caps, AgentSelfUpdateCapabilityV1)
	}
	if chocolateyEnabled {
		caps = append(caps, ChocolateyProviderCapabilityV1)
	}
	return caps
}
