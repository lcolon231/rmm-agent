// SPDX-License-Identifier: AGPL-3.0-only
package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

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
