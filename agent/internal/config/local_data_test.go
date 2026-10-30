// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testLocalFormat  = "nodelink-test-state"
	testLocalVersion = 3
)

// TestProtectLocalDataRoundTrip runs the real platform protector (DPAPI on
// Windows, "none" elsewhere) end to end through the public API.
func TestProtectLocalDataRoundTrip(t *testing.T) {
	plain := []byte(`{"cmd-1":{"output":"local-secret"}}`)
	data, err := ProtectLocalData(testLocalFormat, testLocalVersion, plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	var env ProtectedLocalData
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("envelope is not JSON: %v", err)
	}
	if env.Format != testLocalFormat || env.Version != testLocalVersion || env.Protection != platformProtector.Scheme() {
		t.Fatalf("envelope header = %+v", env)
	}
	if platformProtector.Scheme() != "none" && bytes.Contains(data, []byte("local-secret")) {
		t.Fatalf("protected envelope contains plaintext")
	}

	out, legacy, err := UnprotectLocalData(data, testLocalFormat, testLocalVersion)
	if err != nil {
		t.Fatalf("unprotect: %v", err)
	}
	if legacy {
		t.Fatal("fresh envelope reported as legacy")
	}
	if !bytes.Equal(out, plain) {
		t.Fatalf("round trip = %q, want %q", out, plain)
	}
}

func TestProtectLocalDataRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name    string
		format  string
		version int
		plain   []byte
		want    string
	}{
		{"empty format", "", 1, []byte("x"), "format"},
		{"zero version", testLocalFormat, 0, []byte("x"), "version"},
		{"negative version", testLocalFormat, -1, []byte("x"), "version"},
		{"empty payload", testLocalFormat, 1, nil, "empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := ProtectLocalData(tc.format, tc.version, tc.plain)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if out != nil {
				t.Fatalf("returned data alongside error: %q", out)
			}
		})
	}
}

// TestUnprotectLocalDataFailsClosed covers every envelope defect: each must be
// an error with no plaintext returned, never a silent legacy fallback.
func TestUnprotectLocalDataFailsClosed(t *testing.T) {
	good, err := ProtectLocalData(testLocalFormat, testLocalVersion, []byte(`{"k":"v"}`))
	if err != nil {
		t.Fatal(err)
	}
	var env ProtectedLocalData
	if err := json.Unmarshal(good, &env); err != nil {
		t.Fatal(err)
	}
	mutated := func(mutate func(*ProtectedLocalData)) []byte {
		c := env
		mutate(&c)
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	for _, tc := range []struct {
		name string
		data []byte
		want string
	}{
		{"truncated envelope", good[:len(good)/2], "not valid JSON"},
		{"truncated to one byte", good[:1], "not valid JSON"},
		{"non-JSON bytes", []byte("not json"), "not valid JSON"},
		{"other format", mutated(func(e *ProtectedLocalData) { e.Format = "nodelink-other" }), "format"},
		{"older version", mutated(func(e *ProtectedLocalData) { e.Version = testLocalVersion - 1 }), "version"},
		{"newer version", mutated(func(e *ProtectedLocalData) { e.Version = testLocalVersion + 1 }), "version"},
		{"other protection", mutated(func(e *ProtectedLocalData) { e.Protection = "other-scheme" }), "requires"},
		{"plaintext claiming none", mutated(func(e *ProtectedLocalData) {
			if platformProtector.Scheme() == "none" {
				e.Protection = "dpapi"
			} else {
				e.Protection = "none"
			}
		}), "requires"},
		{"invalid base64", mutated(func(e *ProtectedLocalData) { e.Data = "!!not-base64!!" }), "corrupt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, legacy, err := UnprotectLocalData(tc.data, testLocalFormat, testLocalVersion)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
			if out != nil || legacy {
				t.Fatalf("defective envelope yielded data=%q legacy=%v", out, legacy)
			}
		})
	}
}

// TestUnprotectLocalDataLegacyPlaintext pins the documented migration path:
// well-formed JSON with no envelope is handed back untouched as legacy.
func TestUnprotectLocalDataLegacyPlaintext(t *testing.T) {
	for _, tc := range []struct {
		name string
		data string
	}{
		{"legacy replay map", `{"cmd-1":{"seen_at":"2026-01-01T00:00:00Z"}}`},
		{"empty object", `{}`},
		{"empty format field", `{"format":"","data":"x"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, legacy, err := UnprotectLocalData([]byte(tc.data), testLocalFormat, testLocalVersion)
			if err != nil {
				t.Fatalf("legacy input rejected: %v", err)
			}
			if !legacy || string(out) != tc.data {
				t.Fatalf("got data=%q legacy=%v, want input back as legacy", out, legacy)
			}
		})
	}
}

func TestApplyLocalDataACLOnSavedState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLocalDataACL(path); err != nil {
		t.Fatalf("apply ACL: %v", err)
	}
	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("file unreadable by its writer after ACL: %v", err)
	}
}

// dpapiHeader builds a synthetic DPAPI blob header with the given fields.
func dpapiHeader(version uint32, provider []byte, flags uint32) []byte {
	b := make([]byte, dpapiBlobMinHeader+16)
	binary.LittleEndian.PutUint32(b[0:4], version)
	copy(b[dpapiProviderGUIDOffset:], provider)
	binary.LittleEndian.PutUint32(b[dpapiBlobFlagsOffset:], flags)
	return b
}

func TestCheckDPAPIUserScope(t *testing.T) {
	otherProvider := bytes.Repeat([]byte{0xab}, 16)
	for _, tc := range []struct {
		name string
		blob []byte
		want string // "" means accepted
	}{
		{"user scope", dpapiHeader(1, dpapiProviderGUID, 0x1), ""},
		{"user scope no flags", dpapiHeader(1, dpapiProviderGUID, 0), ""},
		{"machine scope", dpapiHeader(1, dpapiProviderGUID, dpapiFlagLocalMachine), "machine-scoped"},
		{"machine scope with ui forbidden", dpapiHeader(1, dpapiProviderGUID, dpapiFlagLocalMachine|0x1), "machine-scoped"},
		{"unknown version", dpapiHeader(2, dpapiProviderGUID, 0), "version"},
		{"unknown provider", dpapiHeader(1, otherProvider, 0), "provider"},
		{"truncated header", dpapiHeader(1, dpapiProviderGUID, 0)[:dpapiBlobMinHeader-1], "truncated"},
		{"empty", nil, "truncated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDPAPIUserScope(tc.blob)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// The provider GUID bytes must be df9d8cd0-1501-11d1-8c7a-00c04fc297eb in
// Windows GUID layout: the first three groups little endian, the rest as-is.
func TestDPAPIProviderGUIDByteOrder(t *testing.T) {
	raw, err := hex.DecodeString(strings.ReplaceAll("df9d8cd0-1501-11d1-8c7a-00c04fc297eb", "-", ""))
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, 16)
	binary.LittleEndian.PutUint32(want[0:4], binary.BigEndian.Uint32(raw[0:4]))
	binary.LittleEndian.PutUint16(want[4:6], binary.BigEndian.Uint16(raw[4:6]))
	binary.LittleEndian.PutUint16(want[6:8], binary.BigEndian.Uint16(raw[6:8]))
	copy(want[8:], raw[8:])
	if !bytes.Equal(dpapiProviderGUID, want) {
		t.Fatalf("provider GUID bytes = %x, want %x", dpapiProviderGUID, want)
	}
}
