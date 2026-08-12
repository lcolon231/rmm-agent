// SPDX-License-Identifier: AGPL-3.0-only
package protocol

import "testing"

func TestSupportedCapabilitiesAdvertisesShellSession(t *testing.T) {
	caps := SupportedCapabilities()
	found := false
	for _, c := range caps {
		if c == ShellSessionCapabilityV1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("SupportedCapabilities() = %v, want it to include %q", caps, ShellSessionCapabilityV1)
	}
	if ShellSessionCapabilityV1 != "shell-session-v1" {
		t.Fatalf("capability name drift: %q", ShellSessionCapabilityV1)
	}
}

func TestSupportedCapabilitiesAdvertisesPowerOperations(t *testing.T) {
	caps := SupportedCapabilities()
	for _, capability := range caps {
		if capability == PowerOperationsCapabilityV1 {
			return
		}
	}
	t.Fatalf("SupportedCapabilities() = %v, want it to include %q", caps, PowerOperationsCapabilityV1)
}

func TestSupportedCapabilitiesAdvertisesEventLogQuery(t *testing.T) {
	caps := SupportedCapabilities()
	for _, capability := range caps {
		if capability == EventLogQueryCapabilityV1 {
			if EventLogQueryCapabilityV1 != "event-log-query-v1" {
				t.Fatalf("capability name drift: %q", EventLogQueryCapabilityV1)
			}
			return
		}
	}
	t.Fatalf("SupportedCapabilities() = %v, want it to include %q", caps, EventLogQueryCapabilityV1)
}

func TestSupportedCapabilitiesAdvertisesPatchReboot(t *testing.T) {
	caps := SupportedCapabilities()
	for _, capability := range caps {
		if capability == PatchRebootCapabilityV1 {
			if PatchRebootCapabilityV1 != "patch-reboot-v1" {
				t.Fatalf("capability name drift: %q", PatchRebootCapabilityV1)
			}
			return
		}
	}
	t.Fatalf("SupportedCapabilities() = %v, want it to include %q", caps, PatchRebootCapabilityV1)
}

func TestSupportedCapabilitiesAlwaysAdvertisesPackageManagement(t *testing.T) {
	for _, capability := range SupportedCapabilities() {
		if capability == PackageManagementCapabilityV1 {
			if PackageManagementCapabilityV1 != "package-management-v1" {
				t.Fatalf("capability name drift: %q", PackageManagementCapabilityV1)
			}
			return
		}
	}
	t.Fatalf("SupportedCapabilities() must include %q", PackageManagementCapabilityV1)
}

func TestChocolateyCapabilityIsGatedByConfig(t *testing.T) {
	contains := func(caps []string, want string) bool {
		for _, c := range caps {
			if c == want {
				return true
			}
		}
		return false
	}
	if contains(SupportedCapabilitiesWith(false), ChocolateyProviderCapabilityV1) {
		t.Fatal("chocolatey capability must not be advertised when disabled")
	}
	if !contains(SupportedCapabilitiesWith(true), ChocolateyProviderCapabilityV1) {
		t.Fatal("chocolatey capability must be advertised when enabled")
	}
	// The base package-management capability is present either way.
	if !contains(SupportedCapabilitiesWith(false), PackageManagementCapabilityV1) {
		t.Fatal("package-management capability must always be advertised")
	}
}

func TestSupportedCapabilitiesReturnsFreshSlice(t *testing.T) {
	first := SupportedCapabilities()
	if len(first) == 0 {
		t.Fatal("expected at least one capability")
	}
	first[0] = "mutated"
	if SupportedCapabilities()[0] == "mutated" {
		t.Fatal("SupportedCapabilities must return a fresh slice, not shared state")
	}
}
