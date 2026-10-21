// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/client"
	"github.com/lcolon231/rmm/agent/internal/inventory"
)

// inventoryServer records every inventory submission body and answers with
// status/body.
type inventoryServer struct {
	mu    sync.Mutex
	posts []inventory.Submission
	paths []string
	auths []string
}

func newInventoryServer(t *testing.T, status int, respBody string) (*httptest.Server, *inventoryServer) {
	t.Helper()
	rec := &inventoryServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sub inventory.Submission
		_ = json.NewDecoder(r.Body).Decode(&sub)
		rec.mu.Lock()
		rec.posts = append(rec.posts, sub)
		rec.paths = append(rec.paths, r.Method+" "+r.URL.Path)
		rec.auths = append(rec.auths, r.Header.Get("Authorization"))
		rec.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

func testAgent(buf *bytes.Buffer) *Agent {
	return &Agent{log: log.New(buf, "", 0), version: "9.9.9-test"}
}

func TestFatalErrorWrapping(t *testing.T) {
	inner := errors.New("bad config")
	if fatal(nil) != nil {
		t.Fatal("fatal(nil) must stay nil")
	}
	err := fatal(inner)
	if err.Error() != "bad config" {
		t.Fatalf("Error() = %q", err.Error())
	}
	if !errors.Is(err, inner) {
		t.Fatal("Unwrap must expose the cause")
	}
	if !isFatal(err) || isFatal(inner) {
		t.Fatal("isFatal misclassified")
	}
	var fe fatalError
	if !errors.As(err, &fe) || fe.Unwrap() != inner {
		t.Fatal("fatalError.Unwrap mismatch")
	}
}

func TestSubmitInventory(t *testing.T) {
	sections := []inventory.Section{
		{Section: "os", Status: "ok", Payload: map[string]any{"a": 1}},
		{Section: "hardware", Status: "ok", Payload: map[string]any{"b": 2}},
	}
	tests := []struct {
		name         string
		requested    []string
		status       int
		resp         string
		wantErr      bool
		wantPosts    int
		wantSections []string
		wantLog      string
	}{
		{name: "nothing requested", requested: nil, status: 200, resp: `{}`, wantPosts: 0},
		{name: "requested but not collected", requested: []string{"nope"}, status: 200, resp: `{}`, wantPosts: 0},
		{
			name: "subset uploaded and logged", requested: []string{"hardware", "unknown"},
			status: 200, resp: `{"ok":true,"stored_sections":["hardware"]}`,
			wantPosts: 1, wantSections: []string{"hardware"}, wantLog: "inventory stored for sections: hardware",
		},
		{
			name: "all uploaded, nothing stored is silent", requested: []string{"os", "hardware"},
			status: 200, resp: `{"ok":true}`, wantPosts: 1, wantSections: []string{"os", "hardware"},
		},
		{name: "server rejects", requested: []string{"os"}, status: 422, resp: `bad`, wantErr: true, wantPosts: 1, wantSections: []string{"os"}},
		{name: "server error", requested: []string{"os"}, status: 500, resp: `oops`, wantErr: true, wantPosts: 1, wantSections: []string{"os"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, rec := newInventoryServer(t, tt.status, tt.resp)
			var buf bytes.Buffer
			a := testAgent(&buf)
			s := &session{api: client.New(srv.URL, "tok"), inventorySections: sections}
			err := a.submitInventory(context.Background(), s, tt.requested)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(rec.posts) != tt.wantPosts {
				t.Fatalf("posts = %d, want %d", len(rec.posts), tt.wantPosts)
			}
			if tt.wantPosts == 0 {
				return
			}
			if rec.paths[0] != "POST /api/v1/agents/me/inventory" || rec.auths[0] != "Bearer tok" {
				t.Fatalf("request = %q auth %q", rec.paths[0], rec.auths[0])
			}
			sub := rec.posts[0]
			if sub.InventorySchemaVersion != inventory.SchemaVersion || sub.AgentVersion != "9.9.9-test" {
				t.Fatalf("submission header = %+v", sub)
			}
			var got []string
			for _, sec := range sub.Sections {
				got = append(got, sec.Section)
			}
			if strings.Join(got, ",") != strings.Join(tt.wantSections, ",") {
				t.Fatalf("sections = %v, want %v", got, tt.wantSections)
			}
			if tt.wantLog != "" && !strings.Contains(buf.String(), tt.wantLog) {
				t.Fatalf("log = %q, want %q", buf.String(), tt.wantLog)
			}
		})
	}
}

func TestRunUpdateScanSubmission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows runs a real PowerShell Windows Update scan; failure path covered separately")
	}
	tests := []struct {
		name       string
		status     int
		wantStderr string
	}{
		{name: "submitted", status: 200},
		{name: "submission rejected is surfaced on stderr", status: 500, wantStderr: "inventory submission rejected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, rec := newInventoryServer(t, tt.status, `{"ok":true}`)
			var buf bytes.Buffer
			a := testAgent(&buf)
			s := &session{api: client.New(srv.URL, "tok")}
			res := a.runUpdateScan(context.Background(), s)
			if len(rec.posts) != 1 || len(rec.posts[0].Sections) != 1 {
				t.Fatalf("posts = %+v", rec.posts)
			}
			if tt.wantStderr == "" && strings.Contains(res.Stderr, "rejected") {
				t.Fatalf("unexpected stderr %q", res.Stderr)
			}
			if tt.wantStderr != "" {
				if !strings.Contains(res.Stderr, tt.wantStderr) || !strings.Contains(buf.String(), "scan_updates: inventory submission failed") {
					t.Fatalf("stderr = %q, log = %q", res.Stderr, buf.String())
				}
			}
			if !json.Valid([]byte(res.Stdout)) {
				t.Fatalf("stdout is not JSON: %q", res.Stdout)
			}
		})
	}
}

func TestRunUpdateScanCancelledContext(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("non-Windows scan never fails; covered by TestRunUpdateScanSubmission")
	}
	srv, rec := newInventoryServer(t, 200, `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a := testAgent(&bytes.Buffer{})
	res := a.runUpdateScan(ctx, &session{api: client.New(srv.URL, "tok")})
	if res.ExitCode != -1 || !strings.Contains(res.Stderr, "windows update scan failed") {
		t.Fatalf("result = %+v", res)
	}
	if len(rec.posts) != 0 {
		t.Fatal("failed scan must not submit inventory")
	}
}

func TestRunPackageScanFailures(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    string
	}{
		{"invalid payload", `{"bogus":1}`, "scan_packages payload is invalid"},
		{"unsupported provider", `{"provider":"apt"}`, "provider is unsupported"},
		{"chocolatey disabled", `{"provider":"chocolatey"}`, "chocolatey provider is not enabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, rec := newInventoryServer(t, 200, `{}`)
			a := testAgent(&bytes.Buffer{})
			res := a.runPackageScan(context.Background(), &session{api: client.New(srv.URL, "tok")}, json.RawMessage(tt.payload))
			if res.ExitCode != 1 || !strings.Contains(res.Stderr, tt.want) {
				t.Fatalf("result = %+v", res)
			}
			if !json.Valid([]byte(res.Stdout)) {
				t.Fatalf("stdout is not JSON: %q", res.Stdout)
			}
			if len(rec.posts) != 0 {
				t.Fatal("failed scan must not submit inventory")
			}
		})
	}
}

func TestRunPackageScanUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows would invoke the real winget")
	}
	srv, rec := newInventoryServer(t, 200, `{}`)
	a := testAgent(&bytes.Buffer{})
	res := a.runPackageScan(context.Background(), &session{api: client.New(srv.URL, "tok")}, nil)
	if res.ExitCode != 1 || !strings.Contains(res.Stderr, "package scan failed") {
		t.Fatalf("result = %+v", res)
	}
	if len(rec.posts) != 0 {
		t.Fatal("failed discovery must not submit inventory")
	}
}

func TestEnrollIdentity(t *testing.T) {
	t.Run("existing identity refuses re-enroll without calling server", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.json")
		if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		called := false
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
		defer srv.Close()
		_, err := EnrollIdentity(context.Background(), srv.URL, "tok", "n", cfg, "1.0")
		if err == nil || !strings.Contains(err.Error(), "identity already exists") {
			t.Fatalf("err = %v", err)
		}
		if called {
			t.Fatal("server contacted despite existing identity")
		}
	})

	t.Run("server rejection leaves no identity", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.json")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "invalid token", http.StatusForbidden)
		}))
		defer srv.Close()
		_, err := EnrollIdentity(context.Background(), srv.URL, "tok", "n", cfg, "1.0")
		var se *client.StatusError
		if !errors.As(err, &se) || se.StatusCode != http.StatusForbidden {
			t.Fatalf("err = %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "identity.json")); !os.IsNotExist(statErr) {
			t.Fatalf("identity written after failed enroll: %v", statErr)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := EnrollIdentity(ctx, "http://127.0.0.1:1", "tok", "", filepath.Join(t.TempDir(), "config.json"), "1.0")
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("success persists identity", func(t *testing.T) {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.json")
		var gotBody map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v1/enroll" || r.Method != http.MethodPost {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"agent_id":"agent-xyz","agent_token":"tok-xyz","heartbeat_interval_seconds":30,`+
				`"command_public_key":"k","command_envelope_version":"command-v3"}`)
		}))
		defer srv.Close()
		id, err := EnrollIdentity(context.Background(), srv.URL, "enroll-secret", "box", cfg, "1.0")
		if err != nil {
			t.Fatal(err)
		}
		if id.AgentID != "agent-xyz" || id.ServerURL != srv.URL || id.HeartbeatSeconds != 30 {
			t.Fatalf("identity = %+v", id)
		}
		if id.CredentialObtainedAt == "" {
			t.Fatal("CredentialObtainedAt not stamped")
		}
		if _, err := os.Stat(filepath.Join(dir, "identity.json")); err != nil {
			t.Fatalf("identity not persisted: %v", err)
		}
		if gotBody["enrollment_token"] != "enroll-secret" {
			t.Fatalf("enroll body = %v", gotBody)
		}
	})
}

func TestLogPaths(t *testing.T) {
	dir := logDir()
	if !filepath.IsAbs(dir) {
		t.Fatalf("logDir not absolute: %q", dir)
	}
	if got := LogFilePath(); got != filepath.Join(dir, "rmm-agent.log") {
		t.Fatalf("LogFilePath = %q", got)
	}
	if runtime.GOOS == "windows" {
		t.Run("ProgramData override", func(t *testing.T) {
			t.Setenv("ProgramData", t.TempDir())
			want := filepath.Join(os.Getenv("ProgramData"), "NodeLink", "logs")
			if got := logDir(); got != want {
				t.Fatalf("logDir = %q, want %q", got, want)
			}
		})
		t.Run("ProgramData unset", func(t *testing.T) {
			t.Setenv("ProgramData", "")
			if got := logDir(); got != filepath.Join(`C:\ProgramData`, "NodeLink", "logs") {
				t.Fatalf("logDir = %q", got)
			}
		})
	} else if dir != "/var/log/nodelink" {
		t.Fatalf("logDir = %q", dir)
	}
}

func TestConfigNextToExe(t *testing.T) {
	got, err := ConfigNextToExe()
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if filepath.Base(got) != "config.json" || filepath.Dir(got) != filepath.Dir(exe) {
		t.Fatalf("ConfigNextToExe = %q (exe %q)", got, exe)
	}
}

func TestNewFileLoggerWritesToLogDir(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("log directory is fixed at /var/log/nodelink off Windows")
	}
	base := t.TempDir()
	t.Setenv("ProgramData", base)
	logger, closer, err := NewFileLogger()
	if err != nil {
		t.Fatal(err)
	}
	logger.Printf("hello from test")
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(base, "NodeLink", "logs", "rmm-agent.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "hello from test") {
		t.Fatalf("log = %q", data)
	}
}

func TestNewFileLoggerFailsWhenDirIsAFile(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("log directory is fixed off Windows")
	}
	base := t.TempDir()
	// Make %ProgramData%\NodeLink a regular file so MkdirAll fails.
	if err := os.WriteFile(filepath.Join(base, "NodeLink"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ProgramData", base)
	if _, _, err := NewFileLogger(); err == nil {
		t.Fatal("expected error when log directory cannot be created")
	}
}

func TestSubmitInventoryContextCancelled(t *testing.T) {
	srv, _ := newInventoryServer(t, 200, `{}`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	<-ctx.Done()
	a := testAgent(&bytes.Buffer{})
	s := &session{
		api:               client.New(srv.URL, "tok"),
		inventorySections: []inventory.Section{{Section: "os"}},
	}
	if err := a.submitInventory(ctx, s, []string{"os"}); err == nil {
		t.Fatal("expected context error")
	}
}
