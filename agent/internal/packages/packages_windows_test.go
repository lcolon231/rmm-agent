//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package packages

import "testing"

func TestParseWingetList(t *testing.T) {
	output := "" +
		"Name              Id                     Version    Source\n" +
		"-------------------------------------------------------------\n" +
		"Git               Git.Git                2.44.0     winget\n" +
		"PowerShell        Microsoft.PowerShell   7.4.1      winget\n"
	got := parseWingetList(output)
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(got), got)
	}
	if got[0].PackageID != "Git.Git" || got[0].Version != "2.44.0" || got[0].Source != "winget" {
		t.Fatalf("unexpected first row: %+v", got[0])
	}
	if got[1].PackageID != "Microsoft.PowerShell" {
		t.Fatalf("unexpected second row id: %+v", got[1])
	}
}

func TestParseWingetUpgrade(t *testing.T) {
	output := "" +
		"Name       Id            Version   Available   Source\n" +
		"------------------------------------------------------\n" +
		"Git        Git.Git       2.44.0    2.45.0      winget\n" +
		"2 upgrades available.\n"
	got := parseWingetUpgrade(output)
	if len(got) != 1 {
		t.Fatalf("expected 1 upgradable, got %d: %+v", len(got), got)
	}
	if got[0].CurrentVersion != "2.44.0" || got[0].AvailableVersion != "2.45.0" {
		t.Fatalf("unexpected upgrade row: %+v", got[0])
	}
}

func TestParseChocoListAndOutdated(t *testing.T) {
	installed := parseChocoList("googlechrome|123.0\n7zip|22.1\n")
	if len(installed) != 2 || installed[0].PackageID != "googlechrome" || installed[0].Version != "123.0" {
		t.Fatalf("unexpected choco list: %+v", installed)
	}
	outdated := parseChocoOutdated("googlechrome|123.0|124.0|false\n")
	if len(outdated) != 1 || outdated[0].AvailableVersion != "124.0" {
		t.Fatalf("unexpected choco outdated: %+v", outdated)
	}
}

func TestChocoMessageRebootCodes(t *testing.T) {
	if chocoMessage(0) != "ok" {
		t.Fatal("0 should be ok")
	}
	if chocoMessage(3010) == "ok" {
		t.Fatal("3010 should indicate reboot required")
	}
}
