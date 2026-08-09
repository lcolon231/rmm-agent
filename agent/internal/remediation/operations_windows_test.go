//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package remediation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func TestManagedFileUploadDownloadAndRollback(t *testing.T) {
	id, err := newBackupID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(`C:\Windows\Temp\NodeLink`, "issue59-"+id+".bin")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) || os.IsPermission(err) {
			t.Skipf("managed roots require the agent service identity: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("prior"), 0o600); err != nil {
		t.Fatal(err)
	}
	var backupID string
	t.Cleanup(func() {
		_ = os.Remove(path)
		if backupID != "" {
			_ = os.Remove(filepath.Join(journalDir(), backupID+".json"))
		}
	})

	content := []byte("replacement")
	payload, _ := json.Marshal(map[string]any{
		"path": path, "content_base64": base64.StdEncoding.EncodeToString(content),
		"sha256": digest(content), "overwrite": true,
	})
	evidence, err := uploadFile("test-command", payload)
	if err != nil {
		t.Fatal(err)
	}
	backupID, _ = evidence["backup_id"].(string)
	if backupID == "" {
		t.Fatal("upload did not return a backup ID")
	}

	downloadPayload, _ := json.Marshal(map[string]any{"path": path, "expected_sha256": digest(content)})
	download, err := downloadFile(downloadPayload)
	if err != nil {
		t.Fatal(err)
	}
	if download["content_base64"] != base64.StdEncoding.EncodeToString(content) {
		t.Fatalf("unexpected download: %#v", download)
	}

	rollbackPayload, _ := json.Marshal(map[string]any{"backup_id": backupID})
	if _, err := restoreBackup(rollbackPayload); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(path)
	if err != nil || string(restored) != "prior" {
		t.Fatalf("rollback content = %q, err=%v", restored, err)
	}

	tampered, _ := json.Marshal(map[string]any{
		"path": path, "content_base64": base64.StdEncoding.EncodeToString([]byte("tampered")),
		"sha256": digest([]byte("different")), "overwrite": true,
	})
	if _, err := uploadFile("tampered-command", tampered); err == nil {
		t.Fatal("tampered upload was accepted")
	}
}

func TestRegistryWriteDeleteAndRollbackAcrossViews(t *testing.T) {
	for _, view := range []int{32, 64} {
		t.Run(map[int]string{32: "32-bit", 64: "64-bit"}[view], func(t *testing.T) {
			id, err := newBackupID()
			if err != nil {
				t.Fatal(err)
			}
			loc := registryLocation{Hive: "HKCU", Key: `Software\NodeLink\Managed\Tests\` + id, ValueName: "Mode", View: view}
			backupIDs := []string{}
			t.Cleanup(func() {
				root, flags, _ := validateRegistryLocation(loc)
				if key, openErr := registry.OpenKey(root, loc.Key, registry.SET_VALUE|flags); openErr == nil {
					_ = key.DeleteValue(loc.ValueName)
					key.Close()
				}
				_ = registry.DeleteKey(registry.CURRENT_USER, loc.Key)
				for _, backupID := range backupIDs {
					_ = os.Remove(filepath.Join(journalDir(), backupID+".json"))
				}
			})

			writePayload, _ := json.Marshal(map[string]any{
				"hive": loc.Hive, "key": loc.Key, "value_name": loc.ValueName,
				"view": loc.View, "type": "string", "data": "enforced",
			})
			written, err := writeRegistry("write-command", writePayload)
			if err != nil {
				if errors.Is(err, windows.ERROR_ACCESS_DENIED) || os.IsPermission(err) {
					t.Skipf("registry operation requires an unrestricted Windows identity: %v", err)
				}
				t.Fatal(err)
			}
			writeBackup, _ := written["backup_id"].(string)
			backupIDs = append(backupIDs, writeBackup)
			_, value, currentDigest, err := getRegistryValue(loc)
			if err != nil || value != "enforced" {
				t.Fatalf("registry read = %#v, err=%v", value, err)
			}

			deletePayload, _ := json.Marshal(map[string]any{
				"hive": loc.Hive, "key": loc.Key, "value_name": loc.ValueName,
				"view": loc.View, "confirm": true, "expected_current_sha256": currentDigest,
			})
			deleted, err := deleteRegistry("delete-command", deletePayload)
			if err != nil {
				t.Fatal(err)
			}
			deleteBackup, _ := deleted["backup_id"].(string)
			backupIDs = append(backupIDs, deleteBackup)

			rollbackDelete, _ := json.Marshal(map[string]any{"backup_id": deleteBackup})
			if _, err := restoreBackup(rollbackDelete); err != nil {
				t.Fatal(err)
			}
			_, value, _, err = getRegistryValue(loc)
			if err != nil || value != "enforced" {
				t.Fatalf("delete rollback = %#v, err=%v", value, err)
			}

			rollbackWrite, _ := json.Marshal(map[string]any{"backup_id": writeBackup})
			if _, err := restoreBackup(rollbackWrite); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := getRegistryValue(loc); err == nil {
				t.Fatal("write rollback did not remove newly created value")
			}
		})
	}
}
