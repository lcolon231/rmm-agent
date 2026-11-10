// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStatePath(t *testing.T) {
	cases := []struct {
		name, config, want string
	}{
		{"nested", filepath.Join("etc", "rmm", "agent.json"), filepath.Join("etc", "rmm", "monitoring_state.json")},
		{"bare file", "agent.json", "monitoring_state.json"},
		{"empty", "", "monitoring_state.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StatePath(tc.config); got != tc.want {
				t.Fatalf("StatePath(%q) = %q, want %q", tc.config, got, tc.want)
			}
		})
	}
}

func TestPendingBatch(t *testing.T) {
	pending := []Result{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	cases := []struct {
		name    string
		pending []Result
		limit   int
		want    []string
	}{
		{"empty store", nil, 10, nil},
		{"zero limit", pending, 0, nil},
		{"negative limit", pending, -1, nil},
		{"prefix", pending, 2, []string{"a", "b"}},
		{"exact", pending, 3, []string{"a", "b", "c"}},
		{"limit past end", pending, 50, []string{"a", "b", "c"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &Store{Pending: append([]Result(nil), tc.pending...)}
			got := store.PendingBatch(tc.limit)
			if len(got) != len(tc.want) {
				t.Fatalf("PendingBatch(%d) returned %d results, want %d", tc.limit, len(got), len(tc.want))
			}
			for i, id := range tc.want {
				if got[i].ID != id {
					t.Fatalf("PendingBatch(%d)[%d].ID = %q, want %q", tc.limit, i, got[i].ID, id)
				}
			}
			if tc.want == nil && got != nil {
				t.Fatalf("PendingBatch(%d) = %v, want nil", tc.limit, got)
			}
			if len(got) > 0 {
				// The batch is a copy: mutating it must not touch the queue.
				got[0].ID = "mutated"
				if store.Pending[0].ID != tc.pending[0].ID {
					t.Fatalf("PendingBatch aliases the pending queue")
				}
			}
		})
	}
}

func TestLoadStoreRejectsBadState(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"malformed json", "{not json", "decode monitoring state"},
		{"future version", `{"version": 2, "checks": {}}`, "unsupported monitoring state version 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "monitoring_state.json")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadStore(path)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("LoadStore error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadStoreFillsMissingChecks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitoring_state.json")
	if err := os.WriteFile(path, []byte(`{"version": 1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if store.Checks == nil || store.path != path {
		t.Fatalf("LoadStore = %+v, want non-nil checks and path %q", store, path)
	}
}

func TestLoadStoreReportsReadErrors(t *testing.T) {
	// A directory where the file should be is a read error, not "absent".
	_, err := LoadStore(t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "read monitoring state") {
		t.Fatalf("LoadStore error = %v, want a read error", err)
	}
}

func TestSaveReportsFilesystemErrors(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		path    string
		wantErr string
	}{
		// The parent is a regular file, so it cannot be created as a directory.
		{"parent is a file", filepath.Join(blocker, "monitoring_state.json"), "create monitoring state directory"},
		// The temp path is a directory, so the write fails.
		{"temp path is a directory", filepath.Join(dir, "tmpdir"), "write monitoring state"},
		// The destination is a non-empty directory, so the rename fails.
		{"destination is a directory", target, "replace monitoring state"},
	}
	if err := os.Mkdir(filepath.Join(dir, "tmpdir.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &Store{Version: stateVersion, Checks: map[string]CheckState{}, path: tc.path}
			err := store.Save()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Save error = %v, want %q", err, tc.wantErr)
			}
		})
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("failed rename left its temp file behind: %v", err)
	}
}

func TestAcknowledgePrefixRejectsOutOfRangeCounts(t *testing.T) {
	store := &Store{Pending: []Result{{ID: "a"}}, path: filepath.Join(t.TempDir(), "s.json")}
	for _, count := range []int{-1, 2} {
		if err := store.AcknowledgePrefix(count); err == nil {
			t.Fatalf("AcknowledgePrefix(%d) succeeded, want an error", count)
		}
	}
	if len(store.Pending) != 1 {
		t.Fatalf("rejected acknowledgement changed the queue: %+v", store.Pending)
	}
}
