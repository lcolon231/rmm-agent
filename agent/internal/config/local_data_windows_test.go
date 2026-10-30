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

// rawDPAPIProtect calls CryptProtectData directly so tests can mint blobs the
// agent itself never writes (machine scope, extra entropy).
func rawDPAPIProtect(t *testing.T, plain, entropy []byte, flags uint32) []byte {
	t.Helper()
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var ent *windows.DataBlob
	if len(entropy) > 0 {
		ent = &windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, ent, 0, nil, flags, &out); err != nil {
		t.Fatalf("CryptProtectData: %v", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

// localDataEnvelope wraps blob in a dpapi local-state envelope.
func localDataEnvelope(t *testing.T, blob []byte) []byte {
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

func TestDPAPIBlobsAreUserScoped(t *testing.T) {
	blob, err := dpapiProtector{}.Protect([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDPAPIUserScope(blob); err != nil {
		t.Fatalf("agent-written blob failed the scope check: %v", err)
	}
}

// TestUnprotectLocalDataRefusesForeignDPAPIBlobs feeds real DPAPI blobs the
// agent must not trust. A blob from another account cannot be minted on a CI
// runner with one account; a blob bound to different entropy fails in
// CryptUnprotectData the same way (wrong key material), so it stands in.
func TestUnprotectLocalDataRefusesForeignDPAPIBlobs(t *testing.T) {
	plain := []byte(`{"k":"foreign-secret"}`)
	good, err := dpapiProtector{}.Protect(plain)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), good...)
	tampered[len(tampered)-1] ^= 0xff // inside the trailing HMAC/signature
	tamperedBody := append([]byte(nil), good...)
	tamperedBody[len(tamperedBody)/2] ^= 0xff

	for _, tc := range []struct {
		name string
		blob []byte
	}{
		{"machine scope", rawDPAPIProtect(t, plain, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE)},
		{"different key material", rawDPAPIProtect(t, plain, []byte("other-entropy"), windows.CRYPTPROTECT_UI_FORBIDDEN)},
		{"tampered signature", tampered},
		{"tampered ciphertext", tamperedBody},
		{"truncated blob", good[:len(good)/2]},
		{"not a DPAPI blob", []byte("definitely not a DPAPI blob at all, long enough for a header")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, legacy, err := UnprotectLocalData(localDataEnvelope(t, tc.blob), testLocalFormat, testLocalVersion)
			if err == nil || !strings.Contains(err.Error(), "unprotect local state (dpapi)") {
				t.Fatalf("err = %v, want unprotect failure", err)
			}
			if out != nil || legacy {
				t.Fatalf("foreign blob yielded data=%q legacy=%v", out, legacy)
			}
		})
	}

	// Control: the untouched blob in the same envelope decrypts.
	out, _, err := UnprotectLocalData(localDataEnvelope(t, good), testLocalFormat, testLocalVersion)
	if err != nil || !bytes.Equal(out, plain) {
		t.Fatalf("control blob: out=%q err=%v", out, err)
	}
}

// TestLoadIdentityRefusesMachineScopedBlob covers the identity path: a
// machine-scope DPAPI identity (decryptable by any local account) is refused.
func TestLoadIdentityRefusesMachineScopedBlob(t *testing.T) {
	plain, _ := json.Marshal(sampleIdentity())
	blob := rawDPAPIProtect(t, plain, nil, windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE)
	raw, _ := json.Marshal(identityEnvelope{
		Format:     identityFormat,
		Version:    identityFormatVersion,
		Protection: "dpapi",
		Data:       base64.StdEncoding.EncodeToString(blob),
	})
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(path); err == nil || !strings.Contains(err.Error(), "machine-scoped") {
		t.Fatalf("machine-scoped identity err = %v", err)
	}
}

// sddlACEs splits the DACL part of an SDDL string into its control flags and
// ACE strings (without parentheses).
func sddlACEs(t *testing.T, sddl string) (flags string, aces []string) {
	t.Helper()
	i := strings.Index(sddl, "D:")
	if i < 0 {
		t.Fatalf("no DACL in %q", sddl)
	}
	dacl := sddl[i+2:]
	if j := strings.Index(dacl, "S:"); j >= 0 {
		dacl = dacl[:j]
	}
	k := strings.Index(dacl, "(")
	if k < 0 {
		return dacl, nil
	}
	flags = dacl[:k]
	for _, a := range strings.Split(strings.Trim(dacl[k:], "()"), ")(") {
		aces = append(aces, a)
	}
	return flags, aces
}

// TestApplyLocalDataACLReadBack sets an inheritable Everyone grant on the
// parent directory, creates a file that inherits it, applies the ACL, then
// reads the DACL back: it must be protected and hold exactly the explicit
// SYSTEM, Administrators and Owner Rights grants from identityACLSDDL.
func TestApplyLocalDataACLReadBack(t *testing.T) {
	dir := t.TempDir()
	permissive, err := windows.SecurityDescriptorFromString("D:(A;OICI;FA;;;WD)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	permissiveDACL, _, err := permissive.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, permissiveDACL, nil); err != nil {
		t.Fatalf("set permissive parent DACL: %v", err)
	}

	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	readDACL := func() string {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatalf("GetNamedSecurityInfo: %v", err)
		}
		return sd.String()
	}
	if before := readDACL(); !strings.Contains(before, ";WD)") {
		t.Fatalf("precondition: file did not inherit the Everyone grant: %s", before)
	}

	if err := ApplyLocalDataACL(path); err != nil {
		t.Fatalf("ApplyLocalDataACL: %v", err)
	}
	after := readDACL()
	flags, aces := sddlACEs(t, after)
	if !strings.Contains(flags, "P") {
		t.Fatalf("DACL is not protected from inheritance: %s", after)
	}

	got := map[string]bool{}
	for _, ace := range aces {
		f := strings.Split(ace, ";")
		if len(f) != 6 {
			t.Fatalf("unparseable ACE %q in %s", ace, after)
		}
		if f[0] != "A" {
			t.Fatalf("unexpected ACE type in %q: %s", ace, after)
		}
		if strings.Contains(f[1], "ID") {
			t.Fatalf("inherited ACE %q survived: %s", ace, after)
		}
		if f[2] != "FA" && !strings.EqualFold(f[2], "0x1f01ff") {
			t.Fatalf("unexpected rights in %q: %s", ace, after)
		}
		got[f[5]] = true
	}
	want := map[string]bool{"SY": true, "BA": true, "OW": true}
	if len(got) != len(want) || len(aces) != len(want) {
		t.Fatalf("DACL principals = %v (%d ACEs), want exactly SY, BA, OW: %s", got, len(aces), after)
	}
	for sid := range want {
		if !got[sid] {
			t.Fatalf("DACL is missing %s: %s", sid, after)
		}
	}
}

func TestApplyLocalDataACLMissingFile(t *testing.T) {
	err := ApplyLocalDataACL(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil || !strings.Contains(err.Error(), "apply identity ACL") {
		t.Fatalf("err = %v, want apply failure", err)
	}
}
