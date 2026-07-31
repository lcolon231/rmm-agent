//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"context"
	"time"
)

// Uninstall registry enumeration across all three views.
//
// The 64-bit and WOW6432Node paths are read explicitly rather than relying on
// registry redirection, because a 64-bit process sees only the native view by
// default and would miss every 32-bit program — which on a typical Windows
// machine is most of them.
//
// Two classes of row are filtered out at the source: SystemComponent=1 marks
// entries Windows hides from Programs and Features, and a row with no
// DisplayName is a registry artifact rather than an installed program.
const softwareRegistryScript = `
$paths = @(
  @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';            Source = 'machine_x64' },
  @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; Source = 'machine_x86' },
  @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*';            Source = 'user' }
)
$rows = foreach ($entry in $paths) {
  Get-ItemProperty -Path $entry.Path -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName -and -not $_.SystemComponent } |
    ForEach-Object {
      [pscustomobject]@{
        name         = [string]$_.DisplayName
        version      = [string]$_.DisplayVersion
        publisher    = [string]$_.Publisher
        install_date = [string]$_.InstallDate
        identifier   = [string]$_.PSChildName
        source       = $entry.Source
      }
    }
}
@($rows) | ConvertTo-Json -Compress -Depth 3`

// collectSoftware reads the uninstall registry and hands the rows to the
// platform-independent normalizer, which does the dedup, ordering, and
// bounding. Only this function needs Windows; everything that can get the
// answer wrong is testable anywhere.
func collectSoftware(ctx context.Context) (map[string]any, string) {
	rows, err := psJSON(ctx, softwareRegistryScript)
	if err != nil {
		return nil, StatusUnavailable
	}

	raw := make([]RawSoftware, 0, len(rows))
	for _, row := range rows {
		text := func(key string) string {
			value, _ := row[key].(string)
			return value
		}
		raw = append(raw, RawSoftware{
			Name:        text("name"),
			Version:     text("version"),
			Publisher:   text("publisher"),
			InstallDate: text("install_date"),
			Identifier:  text("identifier"),
			Source:      text("source"),
		})
	}

	section := SoftwareSection(raw, time.Now().UTC())
	return section.Payload, section.Status
}
