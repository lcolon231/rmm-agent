//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestLocalDataUsesRealDPAPI: on Windows the local-state envelope must declare
// "dpapi" and must not carry the plaintext anywhere in the file.
func TestLocalDataUsesRealDPAPI(t *testing.T) {
	if platformProtector.Scheme() != "dpapi" {
		t.Fatalf("Windows platform protector is %q, want dpapi", platformProtector.Scheme())
	}
	plain := []byte(`{"cmd-1":{"result":"windows-buffered-secret"}}`)
	raw, err := ProtectLocalData(testLocalFormat, testLocalVersion, plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}
	if bytes.Contains(raw, []byte("windows-buffered-secret")) {
		t.Fatalf("envelope contains plaintext: %s", raw)
	}
	var env ProtectedLocalData
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("windows-buffered-secret")) {
		t.Fatal("DPAPI blob contains plaintext")
	}
	got, legacy, err := UnprotectLocalData(raw, testLocalFormat, testLocalVersion)
	if err != nil || legacy || !bytes.Equal(got, plain) {
		t.Fatalf("round trip = %q legacy=%v err=%v", got, legacy, err)
	}
}

// dpapiProtectWithEntropy produces a genuine DPAPI blob bound to secondary
// entropy the agent never supplies. The agent's Unprotect cannot open it,
// which stands in for a blob protected under key material this process does
// not hold (another user's scope, another machine).
func dpapiProtectWithEntropy(t *testing.T, plain, entropy []byte) []byte {
	t.Helper()
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	ent := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(
		&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out,
	); err != nil {
		t.Fatalf("CryptProtectData: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

func dpapiEnvelope(t *testing.T, blob []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(ProtectedLocalData{
		Format:     testLocalFormat,
		Version:    testLocalVersion,
		Protection: "dpapi",
		Data:       base64.StdEncoding.EncodeToString(blob),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestUnprotectLocalDataRefusesBadDPAPIBlobs: tampered, truncated, and
// foreign-key DPAPI blobs inside a well-formed "dpapi" envelope all fail with
// the unprotect error — never plaintext, never legacy.
func TestUnprotectLocalDataRefusesBadDPAPIBlobs(t *testing.T) {
	plain := []byte("windows-buffered-secret")
	good, err := dpapiProtector{}.Protect(plain)
	if err != nil {
		t.Fatalf("protect: %v", err)
	}

	tampered := append([]byte(nil), good...)
	tampered[len(tampered)/2] ^= 0xff
	tamperedTail := append([]byte(nil), good...)
	tamperedTail[len(tamperedTail)-1] ^= 0x01

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"tampered ciphertext", tampered},
		{"tampered MAC", tamperedTail},
		{"truncated blob", good[:len(good)/2]},
		{"foreign key material", dpapiProtectWithEntropy(t, plain, []byte("not-the-agent"))},
		{"not a DPAPI blob", []byte("definitely not a DPAPI blob")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, legacy, err := UnprotectLocalData(dpapiEnvelope(t, tc.blob), testLocalFormat, testLocalVersion)
			if err == nil || !strings.Contains(err.Error(), "unprotect local state (dpapi)") {
				t.Fatalf("err = %v, want DPAPI unprotect failure", err)
			}
			if out != nil || legacy {
				t.Fatalf("refused blob returned plain=%q legacy=%v", out, legacy)
			}
		})
	}

	// Sanity: the untouched blob still opens, so the failures above come from
	// the mutations, not from the envelope helper.
	if out, _, err := UnprotectLocalData(dpapiEnvelope(t, good), testLocalFormat, testLocalVersion); err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("control blob = %q err=%v", out, err)
	}
}

// TestUnprotectLocalDataRefusesPlaintextSchemeOnWindows: an envelope that
// claims protection "none" (as written by a non-Windows build) is refused by
// the real Windows protector rather than read as plaintext.
func TestUnprotectLocalDataRefusesPlaintextSchemeOnWindows(t *testing.T) {
	raw, err := json.Marshal(ProtectedLocalData{
		Format:     testLocalFormat,
		Version:    testLocalVersion,
		Protection: "none",
		Data:       base64.StdEncoding.EncodeToString([]byte("windows-buffered-secret")),
	})
	if err != nil {
		t.Fatal(err)
	}
	out, legacy, err := UnprotectLocalData(raw, testLocalFormat, testLocalVersion)
	if err == nil || !strings.Contains(err.Error(), `requires "dpapi"`) {
		t.Fatalf("err = %v, want scheme refusal", err)
	}
	if out != nil || legacy {
		t.Fatalf("refused envelope returned plain=%q legacy=%v", out, legacy)
	}
}

// TestLoadIdentityRefusesTamperedDPAPI: the identity path gives the documented
// "re-enroll" error for a tampered or foreign DPAPI identity.
func TestLoadIdentityRefusesTamperedDPAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := sampleIdentity().Save(path); err != nil {
		t.Fatalf("save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env identityEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		t.Fatal(err)
	}

	plainID, _ := json.Marshal(sampleIdentity())
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)/2] ^= 0xff

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"tampered", tampered},
		{"truncated", blob[:len(blob)/2]},
		{"foreign key material", dpapiProtectWithEntropy(t, plainID, []byte("other-account"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := env
			bad.Data = base64.StdEncoding.EncodeToString(tc.blob)
			raw, err := json.Marshal(bad)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			id, err := LoadIdentity(path)
			if err == nil || !strings.Contains(err.Error(), "re-enroll") {
				t.Fatalf("err = %v, want re-enroll guidance", err)
			}
			if id != nil {
				t.Fatalf("refused identity returned %+v", id)
			}
		})
	}
}

// readDACL reads the file's DACL back from the OS and returns it in SDDL form
// along with its control flags.
func readDACL(t *testing.T, path string) (string, windows.SECURITY_DESCRIPTOR_CONTROL) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo: %v", err)
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("security descriptor control: %v", err)
	}
	return sd.String(), control
}

// parseDACL splits the "D:<flags>(ace)(ace)..." part of an SDDL string into
// its flags and the ";"-separated fields of each ACE.
func parseDACL(t *testing.T, sddl string) (flags string, aces [][]string) {
	t.Helper()
	i := strings.Index(sddl, "D:")
	if i < 0 {
		t.Fatalf("no DACL in %q", sddl)
	}
	rest := sddl[i+2:]
	if j := strings.Index(rest, "S:"); j >= 0 {
		rest = rest[:j]
	}
	open := strings.IndexByte(rest, '(')
	if open < 0 {
		return rest, nil
	}
	flags = rest[:open]
	for _, part := range strings.Split(strings.TrimSuffix(rest[open+1:], ")"), ")(") {
		fields := strings.Split(part, ";")
		if len(fields) < 6 {
			t.Fatalf("malformed ACE %q in %q", part, sddl)
		}
		aces = append(aces, fields)
	}
	return flags, aces
}

// TestApplyLocalDataACLRestrictsTempFile applies the ACL to a file created in
// the temp directory (whose permissive ACEs it inherits) and reads the DACL
// back: it must be protected, carry no inherited ACEs, and allow only SYSTEM,
// Administrators and the owner-rights principal.
func TestApplyLocalDataACLRestrictsTempFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ApplyLocalDataACL(path); err != nil {
		t.Fatalf("apply ACL: %v", err)
	}

	sddl, control := readDACL(t, path)
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("DACL is not protected from inheritance: %s", sddl)
	}
	flags, aces := parseDACL(t, sddl)
	if !strings.Contains(flags, "P") {
		t.Fatalf("DACL flags %q lack P (protected): %s", flags, sddl)
	}
	allowed := map[string]bool{"SY": true, "BA": true, "OW": true}
	seen := map[string]bool{}
	for _, ace := range aces {
		aceType, aceFlags, trustee := ace[0], ace[1], ace[5]
		if aceType != "A" {
			t.Fatalf("unexpected ACE type %q in %s", aceType, sddl)
		}
		if strings.Contains(aceFlags, "ID") {
			t.Fatalf("inherited ACE survived: %s", sddl)
		}
		if !allowed[trustee] {
			t.Fatalf("DACL grants access to %q: %s", trustee, sddl)
		}
		seen[trustee] = true
	}
	if !seen["SY"] || !seen["BA"] {
		t.Fatalf("DACL must grant SYSTEM and Administrators: %s", sddl)
	}
}

func TestApplyLocalDataACLMissingFile(t *testing.T) {
	err := ApplyLocalDataACL(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "apply identity ACL") {
		t.Fatalf("err = %v, want apply failure for missing file", err)
	}
}
