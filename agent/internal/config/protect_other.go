//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package config

// plaintextProtector is the non-Windows protection scheme: the identity payload
// is stored unencrypted and confidentiality comes from the 0600 file mode. This
// matches the platform's threat model (Linux/macOS agents are dev/test targets
// today) and is recorded explicitly in the envelope as protection "none" — a
// file that claims "dpapi" is never silently read as plaintext, and vice versa.
type plaintextProtector struct{}

func (plaintextProtector) Scheme() string                     { return "none" }
func (plaintextProtector) Protect(b []byte) ([]byte, error)   { return b, nil }
func (plaintextProtector) Unprotect(b []byte) ([]byte, error) { return b, nil }

var platformProtector protector = plaintextProtector{}

// applyIdentityACL is a no-op off Windows; the 0600 mode set at write time is
// the access control.
func applyIdentityACL(path string) error { return nil }
