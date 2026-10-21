// SPDX-License-Identifier: AGPL-3.0-only
package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const subprocEnv = "NODELINK_TEST_SUBCOMMAND"

// TestSubcommandHelper is not a real test: it is the entry point of the child
// process that runCLI starts. runEnroll and runValidateUpgrade terminate the
// process with os.Exit on failure, so those paths must run out of process.
func TestSubcommandHelper(t *testing.T) {
	sub := os.Getenv(subprocEnv)
	if sub == "" {
		t.Skip("helper process only")
	}
	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	switch sub {
	case "enroll":
		runEnroll(args)
	case "validate-upgrade":
		runValidateUpgrade(args)
	}
	os.Exit(0)
}

// runCLI runs a subcommand in a child process and returns its exit code and
// combined output.
func runCLI(t *testing.T, sub string, env []string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestSubcommandHelper$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), subprocEnv+"="+sub, "AGENT_ENROLLMENT_TOKEN=")
	cmd.Env = append(cmd.Env, env...)
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), string(out)
	}
	if err != nil {
		t.Fatalf("run child: %v", err)
	}
	return 0, string(out)
}

// enrollServer is a minimal enrollment endpoint on loopback HTTP.
func enrollServer(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/api/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"agent_id":"agent-cli","agent_token":"tok","heartbeat_interval_seconds":30,`+
			`"command_public_key":"k","command_envelope_version":"command-v3"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRunEnrollRejectsBadInputs(t *testing.T) {
	tests := []struct {
		name     string
		args     func(dir string) []string
		env      []string
		wantCode int
		wantOut  string
	}{
		{
			name:     "missing server",
			args:     func(string) []string { return []string{"-non-interactive"} },
			wantCode: 2, wantOut: "--server must be an origin URL",
		},
		{
			name: "insecure http server",
			args: func(string) []string {
				return []string{"-server", "http://rmm.example.test", "-non-interactive"}
			},
			wantCode: 2, wantOut: "must use HTTPS",
		},
		{
			name: "credentials in server url",
			args: func(string) []string {
				return []string{"-server", "https://u:p@rmm.example.test", "-non-interactive"}
			},
			wantCode: 2, wantOut: "without credentials",
		},
		{
			name: "no token source",
			args: func(string) []string {
				return []string{"-server", "https://rmm.example.test", "-non-interactive"}
			},
			wantCode: 2, wantOut: "no token available",
		},
		{
			name: "missing token file",
			args: func(dir string) []string {
				return []string{"-server", "https://rmm.example.test", "-token-file", filepath.Join(dir, "nope")}
			},
			wantCode: 2, wantOut: "inspect token file",
		},
		{
			name: "unknown flag",
			args: func(string) []string {
				return []string{"-bogus"}
			},
			wantCode: 2, wantOut: "flag provided but not defined",
		},
		{
			name: "config path unwritable",
			args: func(dir string) []string {
				return []string{
					"-server", "https://rmm.example.test", "-non-interactive",
					"-config", filepath.Join(dir, "missing-dir", "config.json"),
				}
			},
			env:      []string{"AGENT_ENROLLMENT_TOKEN=secret-token"},
			wantCode: 1, wantOut: "save token-free config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			code, out := runCLI(t, "enroll", tt.env, tt.args(dir)...)
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d; output:\n%s", code, tt.wantCode, out)
			}
			if !strings.Contains(out, tt.wantOut) {
				t.Fatalf("output missing %q:\n%s", tt.wantOut, out)
			}
			if strings.Contains(out, "secret-token") {
				t.Fatalf("token leaked into output:\n%s", out)
			}
		})
	}
}

func TestRunEnrollServerFailureAndRefusalToReenroll(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "token consumed", http.StatusForbidden)
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	code, out := runCLI(t, "enroll", []string{"AGENT_ENROLLMENT_TOKEN=secret-token"},
		"-server", srv.URL, "-config", cfg, "-non-interactive")
	if code != 1 || !strings.Contains(out, "403") {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	if strings.Contains(out, "secret-token") {
		t.Fatalf("token leaked:\n%s", out)
	}
	// The token-free config is written before the network call; identity is not.
	if _, err := os.Stat(cfg); err != nil {
		t.Fatalf("token-free config missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); !os.IsNotExist(err) {
		t.Fatalf("identity must not exist after failed enroll: %v", err)
	}

	// An existing identity blocks re-enrollment without contacting the server.
	if err := os.WriteFile(filepath.Join(dir, "identity.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := hits.Load()
	code, out = runCLI(t, "enroll", []string{"AGENT_ENROLLMENT_TOKEN=secret-token"},
		"-server", srv.URL, "-config", cfg, "-non-interactive")
	if code != 1 || !strings.Contains(out, "identity already exists") {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
	if hits.Load() != before {
		t.Fatal("server contacted despite existing identity")
	}
}

// TestEnrollThenValidateUpgrade is the happy path end to end: enroll writes a
// token-free config and protected identity, and the installer's upgrade gate
// then accepts exactly that state.
func TestEnrollThenValidateUpgrade(t *testing.T) {
	var hits atomic.Int32
	srv := enrollServer(t, &hits)
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")

	t.Setenv("NODELINK_TEST_ENROLL_TOKEN", "temporary-secret")
	runEnroll([]string{
		"-server", srv.URL + "/", "-config", cfg, "-name", "box",
		"-token-env", "NODELINK_TEST_ENROLL_TOKEN", "-non-interactive",
	})
	if hits.Load() != 1 {
		t.Fatalf("enroll hits = %d", hits.Load())
	}
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "temporary-secret") || strings.Contains(string(data), "enrollment_token") {
		t.Fatalf("config must be token-free: %s", data)
	}
	if !strings.Contains(string(data), `"server_url": "`+srv.URL+`"`) {
		t.Fatalf("trailing slash not trimmed from server_url: %s", data)
	}
	ident, err := os.ReadFile(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(ident), `"tok"`) {
		t.Fatalf("identity stores the agent token in plaintext: %s", ident)
	}

	runValidateUpgrade([]string{"-config", cfg}) // would os.Exit(1) on failure

	code, out := runCLI(t, "validate-upgrade", nil, "-config", cfg)
	if code != 0 || !strings.Contains(out, "validate-upgrade: ok") {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
}

func TestRunValidateUpgradeRejectsBadState(t *testing.T) {
	writeFile := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) // populates dir/config.json etc.
		wantOut string
	}{
		{
			name:    "missing config",
			setup:   func(*testing.T, string) {},
			wantOut: "upgrade config is not usable",
		},
		{
			name: "malformed config",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"), "{not json")
			},
			wantOut: "parse config",
		},
		{
			name: "config without server_url",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"), `{}`)
			},
			wantOut: "server_url is required",
		},
		{
			name: "invalid update channel",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"),
					`{"server_url":"https://x.test","update":{"channel":"nightly"}}`)
			},
			wantOut: "update.channel",
		},
		{
			name: "config still holds enrollment token",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"),
					`{"server_url":"https://x.test","enrollment_token":"leftover"}`)
			},
			wantOut: "enrollment token",
		},
		{
			name: "missing identity",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"), `{"server_url":"https://x.test"}`)
			},
			wantOut: "read upgrade identity",
		},
		{
			name: "garbage identity",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"), `{"server_url":"https://x.test"}`)
				writeFile(t, filepath.Join(dir, "identity.json"), "garbage")
			},
			wantOut: "upgrade identity is not usable",
		},
		{
			name: "legacy plaintext identity is not a protected envelope",
			setup: func(t *testing.T, dir string) {
				writeFile(t, filepath.Join(dir, "config.json"), `{"server_url":"https://x.test"}`)
				writeFile(t, filepath.Join(dir, "identity.json"),
					`{"agent_id":"a","agent_token":"plaintext-secret","server_url":"https://x.test"}`)
			},
			wantOut: "upgrade identity is not usable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(t, dir)
			code, out := runCLI(t, "validate-upgrade", nil, "-config", filepath.Join(dir, "config.json"))
			if code != 1 {
				t.Fatalf("exit = %d, want 1; output:\n%s", code, out)
			}
			if !strings.Contains(out, "validate-upgrade:") || !strings.Contains(out, tt.wantOut) {
				t.Fatalf("output missing %q:\n%s", tt.wantOut, out)
			}
			if strings.Contains(out, "plaintext-secret") || strings.Contains(out, "leftover") {
				t.Fatalf("secret leaked into output:\n%s", out)
			}
		})
	}
}

func TestRunValidateUpgradeUnknownFlagExits(t *testing.T) {
	code, out := runCLI(t, "validate-upgrade", nil, "-bogus")
	if code != 2 || !strings.Contains(out, "flag provided but not defined") {
		t.Fatalf("exit = %d, output:\n%s", code, out)
	}
}

func TestEnrollmentTokenSources(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		env     string
		file    string
		wantErr string
	}{
		{name: "empty token file", file: empty, wantErr: "token file is empty"},
		{name: "missing token file", file: filepath.Join(dir, "absent"), wantErr: "inspect token file"},
		{name: "no source non-interactive", wantErr: "no token available"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("NODELINK_TEST_TOK", tt.env)
			_, err := enrollmentToken("NODELINK_TEST_TOK", tt.file, false, true)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateServerURLTable(t *testing.T) {
	tests := []struct {
		value string
		ok    bool
	}{
		{"https://rmm.example.test", true},
		{"https://rmm.example.test:8443", true},
		{"http://localhost:8000", true},
		{"http://127.0.0.1", true},
		{"http://[::1]:8000", true},
		{"http://127.0.0.1.evil.test", false},
		{"http://0.0.0.0:8000", false},
		{"ftp://localhost", false},
		// NOTE: ParseRequestURI does not split fragments, so the "#frag" is treated
		// as path and the documented "no fragment" rule is not enforced.
		{"https://rmm.example.test/#frag", true},
		{"https://rmm.example.test?x=1", false},
		{"rmm.example.test", false},
		{"/relative", false},
		{"https://", false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if err := validateServerURL(tt.value); (err == nil) != tt.ok {
				t.Fatalf("validateServerURL(%q) = %v, want ok=%v", tt.value, err, tt.ok)
			}
		})
	}
}
