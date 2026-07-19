//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapiProtector encrypts the identity with Windows DPAPI in user scope, so the
// blob is only decryptable by the account that wrote it — the service identity
// (LocalSystem for the installed service). Enrolling interactively under a
// different account and then starting the service yields a clear unprotect
// error rather than a silent fallback; the recovery is delete + re-enroll.
type dpapiProtector struct{}

// dpapiDescription is stored inside the blob by DPAPI and shown by forensic
// tooling; it carries no secret material.
var dpapiDescription = windows.StringToUTF16Ptr("NodeLink agent identity")

func (dpapiProtector) Scheme() string { return "dpapi" }

func (dpapiProtector) Protect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("refusing to protect empty identity payload")
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(
		&in, dpapiDescription, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out,
	); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func (dpapiProtector) Unprotect(blob []byte) ([]byte, error) {
	if len(blob) == 0 {
		return nil, fmt.Errorf("empty DPAPI blob")
	}
	in := windows.DataBlob{Size: uint32(len(blob)), Data: &blob[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(
		&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out,
	); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

var platformProtector protector = dpapiProtector{}

// identityACLSDDL restricts the identity file to SYSTEM and Administrators,
// with inheritance blocked (D:P) so a permissive parent directory cannot widen
// access to the credential blob.
const identityACLSDDL = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"

// applyIdentityACL replaces the file's DACL with the restricted one above.
func applyIdentityACL(path string) error {
	sd, err := windows.SecurityDescriptorFromString(identityACLSDDL)
	if err != nil {
		return fmt.Errorf("parse identity ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read identity ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		return fmt.Errorf("apply identity ACL: %w", err)
	}
	return nil
}
