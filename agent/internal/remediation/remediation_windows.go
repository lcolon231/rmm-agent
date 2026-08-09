//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package remediation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	maxUploadBytes   = 32 * 1024
	maxDownloadBytes = 64 * 1024
	maxBackupBytes   = 1024 * 1024
	maxRegistryBytes = 16 * 1024
)

type backupRecord struct {
	ID        string          `json:"id"`
	Kind      string          `json:"kind"`
	CreatedAt string          `json:"created_at"`
	File      *fileBackup     `json:"file,omitempty"`
	Registry  *registryBackup `json:"registry,omitempty"`
}

type fileBackup struct {
	Path          string `json:"path"`
	Existed       bool   `json:"existed"`
	ContentBase64 string `json:"content_base64,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
}

type registryBackup struct {
	Hive      string `json:"hive"`
	Key       string `json:"key"`
	ValueName string `json:"value_name"`
	View      int    `json:"view"`
	Existed   bool   `json:"existed"`
	Type      string `json:"type,omitempty"`
	Data      any    `json:"data,omitempty"`
}

func platformExecute(ctx context.Context, commandID, kind string, raw json.RawMessage) (map[string]any, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	switch kind {
	case "file_upload":
		return uploadFile(commandID, raw)
	case "file_download":
		return downloadFile(raw)
	case "registry_read":
		return readRegistry(raw)
	case "registry_write":
		return writeRegistry(commandID, raw)
	case "registry_delete":
		return deleteRegistry(commandID, raw)
	case "remediation_rollback":
		return restoreBackup(raw)
	default:
		return nil, fmt.Errorf("unsupported remediation kind %q", kind)
	}
}

func decodeStrict(raw json.RawMessage, target any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(target); err != nil {
		return fmt.Errorf("invalid payload: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid payload: trailing JSON")
	}
	return nil
}

func managedPath(raw string) (string, error) {
	path, err := validateManagedWindowsPath(raw)
	if err != nil {
		return "", err
	}
	return filepath.Clean(path), nil
}

func rejectReparse(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	rel := strings.TrimPrefix(clean, volume+`\`)
	current := volume + `\`
	for _, part := range strings.Split(rel, `\`) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		ptr, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return fmt.Errorf("inspect path: %w", err)
		}
		attrs, err := windows.GetFileAttributes(ptr)
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect path: %w", err)
		}
		if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("path contains a link or reparse point")
		}
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func atomicWrite(path string, data []byte, replace bool) error {
	if err := rejectReparse(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create managed parent: %w", err)
	}
	if err := rejectReparse(filepath.Dir(path)); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodelink-write-*")
	if err != nil {
		return fmt.Errorf("create atomic temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("destination exists and overwrite is false")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	from, _ := windows.UTF16PtrFromString(tmpPath)
	to, _ := windows.UTF16PtrFromString(path)
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		return fmt.Errorf("commit atomic write: %w", err)
	}
	return nil
}

func uploadFile(commandID string, raw json.RawMessage) (map[string]any, error) {
	var payload struct {
		Path          string `json:"path"`
		ContentBase64 string `json:"content_base64"`
		SHA256        string `json:"sha256"`
		Overwrite     bool   `json:"overwrite"`
	}
	if err := decodeStrict(raw, &payload); err != nil {
		return nil, err
	}
	path, err := managedPath(payload.Path)
	if err != nil {
		return nil, err
	}
	if err := rejectReparse(path); err != nil {
		return nil, err
	}
	data, err := base64.StdEncoding.Strict().DecodeString(payload.ContentBase64)
	if err != nil || len(data) > maxUploadBytes {
		return nil, fmt.Errorf("upload content is invalid or exceeds %d bytes", maxUploadBytes)
	}
	if payload.SHA256 != digest(data) {
		return nil, fmt.Errorf("upload digest mismatch")
	}
	backup, err := backupFile(commandID, path)
	if err != nil {
		return nil, err
	}
	if backup.File.Existed && !payload.Overwrite {
		return nil, fmt.Errorf("destination exists and overwrite is false")
	}
	if err := atomicWrite(path, data, payload.Overwrite); err != nil {
		return nil, err
	}
	if err := persistBackup(backup); err != nil {
		// The mutation happened but rollback evidence did not persist. Restore the
		// captured prior state before reporting failure so this fails closed.
		_ = restoreRecord(backup)
		return nil, fmt.Errorf("persist rollback journal: %w", err)
	}
	return map[string]any{"operation": "file_upload", "path": path, "size": len(data), "sha256": payload.SHA256, "backup_id": backup.ID}, nil
}

func downloadFile(raw json.RawMessage) (map[string]any, error) {
	var payload struct {
		Path           string `json:"path"`
		ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	}
	if err := decodeStrict(raw, &payload); err != nil {
		return nil, err
	}
	path, err := managedPath(payload.Path)
	if err != nil {
		return nil, err
	}
	if err := rejectReparse(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open managed file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxDownloadBytes {
		return nil, fmt.Errorf("download exceeds %d bytes", maxDownloadBytes)
	}
	actual := digest(data)
	if payload.ExpectedSHA256 != "" && payload.ExpectedSHA256 != actual {
		return nil, fmt.Errorf("download digest mismatch")
	}
	return map[string]any{"operation": "file_download", "path": path, "size": len(data), "sha256": actual, "content_base64": base64.StdEncoding.EncodeToString(data)}, nil
}

func newBackupID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func backupFile(commandID, path string) (*backupRecord, error) {
	id, err := newBackupID()
	if err != nil {
		return nil, err
	}
	record := &backupRecord{ID: id, Kind: "file", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), File: &fileBackup{Path: path}}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return record, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxBackupBytes {
		return nil, fmt.Errorf("existing destination cannot be safely backed up")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	record.File.Existed = true
	record.File.ContentBase64 = base64.StdEncoding.EncodeToString(data)
	record.File.SHA256 = digest(data)
	_ = commandID // Command IDs are intentionally not persisted in the journal.
	return record, nil
}

func journalDir() string { return `C:\ProgramData\NodeLink\Rollback` }

func persistBackup(record *backupRecord) error {
	if err := os.MkdirAll(journalDir(), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return atomicJournalWrite(filepath.Join(journalDir(), record.ID+".json"), data)
}

func atomicJournalWrite(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".nodelink-journal-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

type registryLocation struct {
	Hive      string `json:"hive"`
	Key       string `json:"key"`
	ValueName string `json:"value_name"`
	View      int    `json:"view"`
}

func validateRegistryLocation(loc registryLocation) (registry.Key, uint32, error) {
	var root registry.Key
	switch loc.Hive {
	case "HKLM":
		root = registry.LOCAL_MACHINE
	case "HKCU":
		root = registry.CURRENT_USER
	default:
		return 0, 0, fmt.Errorf("registry hive is not allowed")
	}
	key := strings.Trim(strings.ReplaceAll(loc.Key, "/", `\`), `\`)
	folded := strings.ToLower(key)
	const rootKey = `software\nodelink\managed`
	if folded != rootKey && !strings.HasPrefix(folded, rootKey+`\`) {
		return 0, 0, fmt.Errorf("registry key is outside the managed subtree")
	}
	if strings.Contains(key, `..`) || strings.ContainsRune(loc.ValueName, 0) || strings.Contains(loc.ValueName, `\`) {
		return 0, 0, fmt.Errorf("registry location is invalid")
	}
	var view uint32
	switch loc.View {
	case 32:
		view = registry.WOW64_32KEY
	case 64:
		view = registry.WOW64_64KEY
	default:
		return 0, 0, fmt.Errorf("registry view must be 32 or 64")
	}
	return root, view, nil
}

func readRegistry(raw json.RawMessage) (map[string]any, error) {
	var loc registryLocation
	if err := decodeStrict(raw, &loc); err != nil {
		return nil, err
	}
	valueType, data, valueDigest, err := getRegistryValue(loc)
	if err != nil {
		return nil, err
	}
	return map[string]any{"operation": "registry_read", "hive": loc.Hive, "key": loc.Key, "value_name": loc.ValueName, "view": loc.View, "type": valueType, "data": data, "sha256": valueDigest}, nil
}

func getRegistryValue(loc registryLocation) (string, any, string, error) {
	root, view, err := validateRegistryLocation(loc)
	if err != nil {
		return "", nil, "", err
	}
	key, err := registry.OpenKey(root, loc.Key, registry.QUERY_VALUE|view)
	if err != nil {
		return "", nil, "", fmt.Errorf("open registry key: %w", err)
	}
	defer key.Close()
	_, nativeType, err := key.GetValue(loc.ValueName, nil)
	if err != nil {
		return "", nil, "", fmt.Errorf("read registry value: %w", err)
	}
	var valueType string
	var data any
	switch nativeType {
	case registry.SZ:
		valueType = "string"
		data, _, err = key.GetStringValue(loc.ValueName)
	case registry.EXPAND_SZ:
		valueType = "expand_string"
		data, _, err = key.GetStringValue(loc.ValueName)
	case registry.DWORD:
		valueType = "dword"
		data, _, err = key.GetIntegerValue(loc.ValueName)
	case registry.QWORD:
		valueType = "qword"
		data, _, err = key.GetIntegerValue(loc.ValueName)
	case registry.MULTI_SZ:
		valueType = "multi_string"
		data, _, err = key.GetStringsValue(loc.ValueName)
	case registry.BINARY:
		valueType = "binary"
		var b []byte
		b, _, err = key.GetBinaryValue(loc.ValueName)
		if len(b) > maxRegistryBytes {
			return "", nil, "", fmt.Errorf("registry binary value is oversized")
		}
		data = base64.StdEncoding.EncodeToString(b)
	default:
		return "", nil, "", fmt.Errorf("registry value type %d is unsupported", nativeType)
	}
	if err != nil {
		return "", nil, "", fmt.Errorf("read registry value: %w", err)
	}
	canonical, _ := json.Marshal(map[string]any{"type": valueType, "data": data})
	return valueType, data, digest(canonical), nil
}

func captureRegistryBackup(loc registryLocation) (*backupRecord, error) {
	id, err := newBackupID()
	if err != nil {
		return nil, err
	}
	record := &backupRecord{ID: id, Kind: "registry", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), Registry: &registryBackup{Hive: loc.Hive, Key: loc.Key, ValueName: loc.ValueName, View: loc.View}}
	typeName, data, _, err := getRegistryValue(loc)
	if errors.Is(err, registry.ErrNotExist) || (err != nil && strings.Contains(err.Error(), "file does not exist")) {
		return record, nil
	}
	if err != nil {
		return nil, err
	}
	record.Registry.Existed = true
	record.Registry.Type = typeName
	record.Registry.Data = data
	return record, nil
}

func writeRegistry(commandID string, raw json.RawMessage) (map[string]any, error) {
	var payload struct {
		registryLocation
		Type     string `json:"type"`
		Data     any    `json:"data"`
		Expected string `json:"expected_current_sha256,omitempty"`
	}
	if err := decodeStrict(raw, &payload); err != nil {
		return nil, err
	}
	loc := payload.registryLocation
	if payload.Expected != "" {
		_, _, current, err := getRegistryValue(loc)
		if err != nil {
			return nil, err
		}
		if current != payload.Expected {
			return nil, fmt.Errorf("registry compare-and-set digest mismatch")
		}
	}
	backup, err := captureRegistryBackup(loc)
	if err != nil {
		return nil, err
	}
	if err := setRegistryValue(loc, payload.Type, payload.Data); err != nil {
		return nil, err
	}
	if err := persistBackup(backup); err != nil {
		_ = restoreRecord(backup)
		return nil, fmt.Errorf("persist rollback journal: %w", err)
	}
	_, _, valueDigest, _ := getRegistryValue(loc)
	_ = commandID
	return map[string]any{"operation": "registry_write", "hive": loc.Hive, "key": loc.Key, "value_name": loc.ValueName, "view": loc.View, "type": payload.Type, "sha256": valueDigest, "backup_id": backup.ID}, nil
}

func setRegistryValue(loc registryLocation, valueType string, data any) error {
	root, view, err := validateRegistryLocation(loc)
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(root, loc.Key, registry.SET_VALUE|view)
	if err != nil {
		return fmt.Errorf("create registry key: %w", err)
	}
	defer key.Close()
	switch valueType {
	case "string", "expand_string":
		value, ok := data.(string)
		if !ok || len([]byte(value)) > maxRegistryBytes {
			return fmt.Errorf("registry string data is invalid")
		}
		if valueType == "expand_string" {
			return key.SetExpandStringValue(loc.ValueName, value)
		}
		return key.SetStringValue(loc.ValueName, value)
	case "dword", "qword":
		var value uint64
		switch raw := data.(type) {
		case json.Number:
			parsed, err := raw.Int64()
			if err != nil || parsed < 0 {
				return fmt.Errorf("registry integer data is invalid")
			}
			value = uint64(parsed)
		case float64: // compatibility with an older locally persisted journal
			if raw < 0 || raw != float64(uint64(raw)) {
				return fmt.Errorf("registry integer data is invalid")
			}
			value = uint64(raw)
		default:
			return fmt.Errorf("registry integer data is invalid")
		}
		if valueType == "dword" {
			if value > 0xffffffff {
				return fmt.Errorf("registry dword is out of range")
			}
			return key.SetDWordValue(loc.ValueName, uint32(value))
		}
		return key.SetQWordValue(loc.ValueName, value)
	case "multi_string":
		rawItems, ok := data.([]any)
		if !ok || len(rawItems) > 256 {
			return fmt.Errorf("registry multi-string data is invalid")
		}
		items := make([]string, len(rawItems))
		for i, item := range rawItems {
			var ok bool
			items[i], ok = item.(string)
			if !ok || strings.ContainsRune(items[i], 0) {
				return fmt.Errorf("registry multi-string data is invalid")
			}
		}
		return key.SetStringsValue(loc.ValueName, items)
	case "binary":
		encoded, ok := data.(string)
		if !ok {
			return fmt.Errorf("registry binary data is invalid")
		}
		value, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(value) > maxRegistryBytes {
			return fmt.Errorf("registry binary data is invalid")
		}
		return key.SetBinaryValue(loc.ValueName, value)
	default:
		return fmt.Errorf("registry type is unsupported")
	}
}

func deleteRegistry(commandID string, raw json.RawMessage) (map[string]any, error) {
	var payload struct {
		registryLocation
		Confirm  bool   `json:"confirm"`
		Expected string `json:"expected_current_sha256,omitempty"`
	}
	if err := decodeStrict(raw, &payload); err != nil {
		return nil, err
	}
	if !payload.Confirm {
		return nil, fmt.Errorf("registry deletion was not explicitly confirmed")
	}
	loc := payload.registryLocation
	_, _, current, err := getRegistryValue(loc)
	if err != nil {
		return nil, err
	}
	if payload.Expected != "" && current != payload.Expected {
		return nil, fmt.Errorf("registry compare-and-delete digest mismatch")
	}
	backup, err := captureRegistryBackup(loc)
	if err != nil {
		return nil, err
	}
	root, view, _ := validateRegistryLocation(loc)
	key, err := registry.OpenKey(root, loc.Key, registry.SET_VALUE|view)
	if err != nil {
		return nil, err
	}
	err = key.DeleteValue(loc.ValueName)
	key.Close()
	if err != nil {
		return nil, err
	}
	if err := persistBackup(backup); err != nil {
		_ = restoreRecord(backup)
		return nil, fmt.Errorf("persist rollback journal: %w", err)
	}
	_ = commandID
	return map[string]any{"operation": "registry_delete", "hive": loc.Hive, "key": loc.Key, "value_name": loc.ValueName, "view": loc.View, "deleted_sha256": current, "backup_id": backup.ID}, nil
}

func restoreBackup(raw json.RawMessage) (map[string]any, error) {
	var payload struct {
		BackupID string `json:"backup_id"`
	}
	if err := decodeStrict(raw, &payload); err != nil {
		return nil, err
	}
	if len(payload.BackupID) != 32 {
		return nil, fmt.Errorf("backup ID is invalid")
	}
	if _, err := hex.DecodeString(payload.BackupID); err != nil {
		return nil, fmt.Errorf("backup ID is invalid")
	}
	data, err := os.ReadFile(filepath.Join(journalDir(), payload.BackupID+".json"))
	if err != nil {
		return nil, fmt.Errorf("read rollback journal: %w", err)
	}
	var record backupRecord
	journalDecoder := json.NewDecoder(bytes.NewReader(data))
	journalDecoder.UseNumber()
	if err := journalDecoder.Decode(&record); err != nil || record.ID != payload.BackupID {
		return nil, fmt.Errorf("rollback journal is invalid")
	}
	if err := restoreRecord(&record); err != nil {
		return nil, err
	}
	return map[string]any{"operation": "remediation_rollback", "backup_id": record.ID, "resource_kind": record.Kind, "restored": true}, nil
}

func restoreRecord(record *backupRecord) error {
	switch record.Kind {
	case "file":
		if record.File == nil {
			return fmt.Errorf("file rollback journal is incomplete")
		}
		path, err := managedPath(record.File.Path)
		if err != nil {
			return err
		}
		if !record.File.Existed {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		data, err := base64.StdEncoding.Strict().DecodeString(record.File.ContentBase64)
		if err != nil || digest(data) != record.File.SHA256 {
			return fmt.Errorf("file rollback content failed digest validation")
		}
		return atomicWrite(path, data, true)
	case "registry":
		if record.Registry == nil {
			return fmt.Errorf("registry rollback journal is incomplete")
		}
		loc := registryLocation{Hive: record.Registry.Hive, Key: record.Registry.Key, ValueName: record.Registry.ValueName, View: record.Registry.View}
		if !record.Registry.Existed {
			root, view, err := validateRegistryLocation(loc)
			if err != nil {
				return err
			}
			key, err := registry.OpenKey(root, loc.Key, registry.SET_VALUE|view)
			if errors.Is(err, registry.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			defer key.Close()
			err = key.DeleteValue(loc.ValueName)
			if errors.Is(err, registry.ErrNotExist) {
				return nil
			}
			return err
		}
		return setRegistryValue(loc, record.Registry.Type, record.Registry.Data)
	default:
		return fmt.Errorf("rollback resource kind is unsupported")
	}
}
