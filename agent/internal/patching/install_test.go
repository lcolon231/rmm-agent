// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"context"
	"runtime"
	"testing"
)

func TestInstallUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping unsupported test on Windows host")
	}
	res, err := Install(context.Background(), InstallTargets{KBIDs: []string{"KB5034123"}})
	if err == nil {
		t.Fatal("expected error on non-windows platform, got nil")
	}
	if res.Status != "unsupported" {
		t.Fatalf("expected status 'unsupported', got %s", res.Status)
	}
}

func TestInstallWindowsTargetNotFound(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("skipping Windows test on non-windows host")
	}
	res, err := Install(context.Background(), InstallTargets{KBIDs: []string{"KB9999999"}})
	if err != nil {
		t.Fatalf("install failed unexpectedly: %v", err)
	}
	if res.Status != "failed" {
		t.Fatalf("expected status 'failed', got %s: %s", res.Status, res.Message)
	}
}

func TestNormalizeInstallTargetsSupportsKBAndUpdateID(t *testing.T) {
	targets, err := NormalizeInstallTargets(InstallTargets{
		KBIDs:     []string{"5034123", "kb5034123"},
		UpdateIDs: []string{"12345678-1234-ABCD-9876-1234567890AB"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets.KBIDs) != 1 || targets.KBIDs[0] != "KB5034123" {
		t.Fatalf("KB targets not normalized and deduplicated: %+v", targets.KBIDs)
	}
	if len(targets.UpdateIDs) != 1 || targets.UpdateIDs[0] != "12345678-1234-abcd-9876-1234567890ab" {
		t.Fatalf("Update ID not normalized: %+v", targets.UpdateIDs)
	}
}

func TestNormalizeInstallTargetsRequiresExplicitScope(t *testing.T) {
	if _, err := NormalizeInstallTargets(InstallTargets{}); err == nil {
		t.Fatal("empty target selection must fail closed")
	}
	if _, err := NormalizeInstallTargets(InstallTargets{All: true, KBIDs: []string{"KB5034123"}}); err == nil {
		t.Fatal("install_all combined with identifiers must be rejected")
	}
	if _, err := NormalizeInstallTargets(InstallTargets{UpdateIDs: []string{"not-a-guid"}}); err == nil {
		t.Fatal("malformed Update ID must be rejected")
	}
	all, err := NormalizeInstallTargets(InstallTargets{All: true})
	if err != nil || !all.All {
		t.Fatalf("explicit install_all should be accepted: %+v, %v", all, err)
	}
}
