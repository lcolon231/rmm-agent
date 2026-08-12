//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package packages

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	// discoverTimeout bounds a single discovery invocation.
	discoverTimeout = 3 * time.Minute
	// perPackageTimeout bounds a single package install/upgrade. Installs can be
	// large, so this is generous; the batch is still bounded by the number of
	// targets (MaxPackageTargets) and the command's own lifetime.
	perPackageTimeout = 10 * time.Minute
)

// runBounded executes a provider CLI with a timeout, returning combined output
// and the process exit code (0 on success, the child's code otherwise, -1 when
// the process could not be run at all).
func runBounded(ctx context.Context, timeout time.Duration, name string, args ...string) (string, int, error) {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(bounded, name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err == nil {
		return text, 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return text, exitErr.ExitCode(), err
	}
	return text, -1, err
}

// ---- Winget ----

func platformWingetDiscover(ctx context.Context) ([]InstalledPackage, []UpgradablePackage, error) {
	installedOut, _, err := runBounded(ctx, discoverTimeout,
		"winget.exe", "list", "--accept-source-agreements", "--disable-interactivity")
	if err != nil {
		return nil, nil, fmt.Errorf("winget list failed: %w", err)
	}
	upgradeOut, _, _ := runBounded(ctx, discoverTimeout,
		"winget.exe", "upgrade", "--accept-source-agreements", "--disable-interactivity")

	installed := parseWingetList(installedOut)
	upgradable := parseWingetUpgrade(upgradeOut)
	return installed, upgradable, nil
}

func platformWingetInstall(ctx context.Context, operation string, ids []string) ([]PackageOutcome, error) {
	verb := "install"
	if operation == OperationUpgrade {
		verb = "upgrade"
	}
	outcomes := make([]PackageOutcome, 0, len(ids))
	for _, id := range ids {
		_, code, _ := runBounded(ctx, perPackageTimeout,
			"winget.exe", verb, "--exact", "--id", id,
			"--accept-source-agreements", "--accept-package-agreements",
			"--disable-interactivity", "--silent")
		outcomes = append(outcomes, PackageOutcome{
			PackageID:  id,
			Operation:  operation,
			ResultCode: code,
			Message:    wingetMessage(code),
		})
	}
	return outcomes, nil
}

func wingetMessage(code int) string {
	if code == 0 {
		return "ok"
	}
	return fmt.Sprintf("winget exited with code %d", code)
}

// parseWingetColumns finds the byte offsets of the winget table's columns from
// its header row. winget renders a fixed-width table with a "----" separator; we
// key off the header cells so a shifted layout still lands on the right columns.
func parseWingetColumns(header string) map[string]int {
	cols := map[string]int{}
	for _, name := range []string{"Name", "Id", "Version", "Available", "Source"} {
		if idx := strings.Index(header, name); idx >= 0 {
			cols[name] = idx
		}
	}
	return cols
}

func sliceColumn(line string, start int, ends []int) string {
	if start < 0 || start >= len(line) {
		return ""
	}
	end := len(line)
	for _, candidate := range ends {
		if candidate > start && candidate < end {
			end = candidate
		}
	}
	if end > len(line) {
		end = len(line)
	}
	return strings.TrimSpace(line[start:end])
}

func parseWingetList(output string) []InstalledPackage {
	header, rows := wingetHeaderRows(output)
	if header == "" {
		return nil
	}
	cols := parseWingetColumns(header)
	nameC, idC, verC, srcC := cols["Name"], cols["Id"], cols["Version"], cols["Source"]
	out := []InstalledPackage{}
	for _, line := range rows {
		id := sliceColumn(line, idC, []int{verC, cols["Available"], srcC})
		version := sliceColumn(line, verC, []int{cols["Available"], srcC})
		// A real row has both a valid id and a version; a trailing summary line
		// ("N upgrades available.") is shorter than the version column and so
		// yields an empty version, which filters it out.
		if !packageIDPattern.MatchString(id) || version == "" {
			continue
		}
		out = append(out, InstalledPackage{
			PackageID: id,
			Name:      sliceColumn(line, nameC, []int{idC}),
			Version:   version,
			Source:    sliceColumn(line, srcC, nil),
		})
		if len(out) >= MaxPackageTargets*10 {
			break
		}
	}
	return out
}

func parseWingetUpgrade(output string) []UpgradablePackage {
	header, rows := wingetHeaderRows(output)
	if header == "" {
		return nil
	}
	cols := parseWingetColumns(header)
	nameC, idC, verC, availC, srcC := cols["Name"], cols["Id"], cols["Version"], cols["Available"], cols["Source"]
	if availC == 0 {
		return nil // no "Available" column means this was not an upgrade table
	}
	out := []UpgradablePackage{}
	for _, line := range rows {
		id := sliceColumn(line, idC, []int{verC, availC, srcC})
		available := sliceColumn(line, availC, []int{srcC})
		// A real upgrade row has a valid id and an available version; the trailing
		// "N upgrades available." summary is shorter than the Available column and
		// so is filtered out here.
		if !packageIDPattern.MatchString(id) || available == "" {
			continue
		}
		out = append(out, UpgradablePackage{
			PackageID:        id,
			Name:             sliceColumn(line, nameC, []int{idC}),
			CurrentVersion:   sliceColumn(line, verC, []int{availC, srcC}),
			AvailableVersion: available,
			Source:           sliceColumn(line, srcC, nil),
		})
		if len(out) >= MaxPackageTargets*10 {
			break
		}
	}
	return out
}

// wingetHeaderRows returns the header line and the data rows below the "----"
// separator, skipping winget's progress spinner lines.
func wingetHeaderRows(output string) (string, []string) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var header string
	var rows []string
	sawSeparator := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "Name") && strings.Contains(trimmed, "Id") {
			header = line
			continue
		}
		if header != "" && strings.HasPrefix(trimmed, "---") {
			sawSeparator = true
			continue
		}
		if sawSeparator {
			// A trailing summary line ("N upgrades available.") has no column data.
			if !strings.ContainsAny(line, " \t") && len(line) < 3 {
				continue
			}
			rows = append(rows, line)
		}
	}
	return header, rows
}

// ---- Chocolatey ----

func platformChocoDiscover(ctx context.Context) ([]InstalledPackage, []UpgradablePackage, error) {
	installedOut, _, err := runBounded(ctx, discoverTimeout,
		"choco.exe", "list", "--local-only", "--limit-output", "--no-color")
	if err != nil {
		return nil, nil, fmt.Errorf("choco list failed: %w", err)
	}
	outdatedOut, _, _ := runBounded(ctx, discoverTimeout,
		"choco.exe", "outdated", "--limit-output", "--no-color")

	return parseChocoList(installedOut), parseChocoOutdated(outdatedOut), nil
}

func platformChocoInstall(ctx context.Context, operation string, ids []string) ([]PackageOutcome, error) {
	verb := "install"
	if operation == OperationUpgrade {
		verb = "upgrade"
	}
	outcomes := make([]PackageOutcome, 0, len(ids))
	for _, id := range ids {
		_, code, _ := runBounded(ctx, perPackageTimeout,
			"choco.exe", verb, id, "--yes", "--limit-output", "--no-progress", "--no-color")
		outcomes = append(outcomes, PackageOutcome{
			PackageID:  id,
			Operation:  operation,
			ResultCode: code,
			Message:    chocoMessage(code),
		})
	}
	return outcomes, nil
}

func chocoMessage(code int) string {
	if code == 0 {
		return "ok"
	}
	// 1641/3010 are Windows Installer reboot-required codes chocolatey passes through.
	if code == 1641 || code == 3010 {
		return fmt.Sprintf("succeeded, reboot required (code %d)", code)
	}
	return fmt.Sprintf("choco exited with code %d", code)
}

// parseChocoList parses `choco list --limit-output` lines of "name|version".
func parseChocoList(output string) []InstalledPackage {
	out := []InstalledPackage{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), "|")
		if len(fields) < 2 || fields[0] == "" {
			continue
		}
		out = append(out, InstalledPackage{
			PackageID: fields[0],
			Name:      fields[0],
			Version:   fields[1],
			Source:    ProviderChocolatey,
		})
		if len(out) >= MaxPackageTargets*10 {
			break
		}
	}
	return out
}

// parseChocoOutdated parses `choco outdated --limit-output` lines of
// "name|current|available|pinned".
func parseChocoOutdated(output string) []UpgradablePackage {
	out := []UpgradablePackage{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), "|")
		if len(fields) < 3 || fields[0] == "" {
			continue
		}
		out = append(out, UpgradablePackage{
			PackageID:        fields[0],
			Name:             fields[0],
			CurrentVersion:   fields[1],
			AvailableVersion: fields[2],
			Source:           ProviderChocolatey,
		})
		if len(out) >= MaxPackageTargets*10 {
			break
		}
	}
	return out
}
