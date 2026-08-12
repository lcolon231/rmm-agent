// SPDX-License-Identifier: AGPL-3.0-only
package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestClearEnrollmentTokenRemovesPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg := &Config{
		ServerURL:        "https://rmm.example.test",
		EnrollmentToken:  "temporary-bootstrap-secret",
		HeartbeatSeconds: 60,
	}
	if err := ClearEnrollmentToken(path, cfg); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "temporary-bootstrap-secret") {
		t.Fatal("plaintext enrollment token remained in config")
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.EnrollmentToken != "" || loaded.ServerURL != cfg.ServerURL {
		t.Fatalf("unexpected scrubbed config: %#v", loaded)
	}
}

func TestLoadTLSSPKIPins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	data := []byte(`{
  "server_url": "https://rmm.example",
  "enrollment_token": "token",
  "tls_spki_pins": ["sha256/current", "sha256/next"]
}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sha256/current", "sha256/next"}
	if !reflect.DeepEqual(loaded.TLSSPKIPins, want) {
		t.Fatalf("tls_spki_pins = %v, want %v", loaded.TLSSPKIPins, want)
	}
}

func TestLoadWithoutTLSSPKIPinsKeepsPinningDisabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"server_url":"https://rmm.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.TLSSPKIPins) != 0 {
		t.Fatalf("tls_spki_pins = %v, want disabled", loaded.TLSSPKIPins)
	}
}

func TestLoadUpdateChannel(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	for _, channel := range []string{"stable", "beta", "canary"} {
		loaded, err := Load(write(t, `{"server_url":"https://rmm.example","update":{"channel":"`+channel+`"}}`))
		if err != nil {
			t.Fatalf("channel %q: %v", channel, err)
		}
		if loaded.Update.Channel != channel {
			t.Fatalf("channel = %q, want %q", loaded.Update.Channel, channel)
		}
	}

	// Absent means the default stable channel, reported as empty so the agent
	// omits it and the server's stored value is left untouched.
	loaded, err := Load(write(t, `{"server_url":"https://rmm.example"}`))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Update.Channel != "" {
		t.Fatalf("absent channel = %q, want empty", loaded.Update.Channel)
	}

	// A typo must not silently become "no channel" or a wildcard.
	if _, err := Load(write(t, `{"server_url":"https://rmm.example","update":{"channel":"nightly"}}`)); err == nil {
		t.Fatal("an unknown update channel must refuse to start")
	}
}
