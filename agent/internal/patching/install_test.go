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
	res, err := Install(context.Background(), []string{"KB5034123"})
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
	res, err := Install(context.Background(), []string{"KB9999999"})
	if err != nil {
		t.Fatalf("install failed unexpectedly: %v", err)
	}
	if res.Status != "success" {
		t.Fatalf("expected status 'success', got %s: %s", res.Status, res.Message)
	}
}
