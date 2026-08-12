//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only
package packages

import (
	"context"
	"fmt"
)

func platformWingetDiscover(_ context.Context) ([]InstalledPackage, []UpgradablePackage, error) {
	return nil, nil, fmt.Errorf("winget package discovery is unsupported on this platform")
}

func platformWingetInstall(_ context.Context, _ string, _ []string) ([]PackageOutcome, error) {
	return nil, fmt.Errorf("winget package installation is unsupported on this platform")
}

func platformChocoDiscover(_ context.Context) ([]InstalledPackage, []UpgradablePackage, error) {
	return nil, nil, fmt.Errorf("chocolatey package discovery is unsupported on this platform")
}

func platformChocoInstall(_ context.Context, _ string, _ []string) ([]PackageOutcome, error) {
	return nil, fmt.Errorf("chocolatey package installation is unsupported on this platform")
}
