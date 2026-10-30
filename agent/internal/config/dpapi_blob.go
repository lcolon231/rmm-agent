// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// DPAPI blob header layout (CryptProtectData output), little endian:
//
//	0  dwVersion           uint32 (always 1)
//	4  guidProvider        GUID   (df9d8cd0-1501-11d1-8c7a-00c04fc297eb)
//	20 dwMasterKeyVersion  uint32
//	24 guidMasterKey       GUID
//	40 dwFlags             uint32 (the CRYPTPROTECT_* flags the blob was made with)
//
// Parsing lives in an untagged file so every CI job covers it, not just Windows.
const (
	dpapiBlobVersion        = 1
	dpapiBlobFlagsOffset    = 40
	dpapiBlobMinHeader      = dpapiBlobFlagsOffset + 4
	dpapiFlagLocalMachine   = 0x4 // CRYPTPROTECT_LOCAL_MACHINE
	dpapiProviderGUIDOffset = 4
)

// dpapiProviderGUID is the default DPAPI provider in its on-disk byte order.
var dpapiProviderGUID = []byte{
	0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11,
	0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
}

// checkDPAPIUserScope refuses a blob that is not a recognizable DPAPI blob or
// that was protected in machine scope. A machine-scope blob is decryptable by
// every account on the host, so accepting one would let any local user plant
// state the service then trusts; agent state is only ever written in the
// service account's user scope.
func checkDPAPIUserScope(blob []byte) error {
	if len(blob) < dpapiBlobMinHeader {
		return fmt.Errorf("DPAPI blob is truncated (%d bytes)", len(blob))
	}
	if v := binary.LittleEndian.Uint32(blob[0:4]); v != dpapiBlobVersion {
		return fmt.Errorf("DPAPI blob version %d is not supported", v)
	}
	if !bytes.Equal(blob[dpapiProviderGUIDOffset:dpapiProviderGUIDOffset+16], dpapiProviderGUID) {
		return fmt.Errorf("DPAPI blob has an unknown provider")
	}
	if binary.LittleEndian.Uint32(blob[dpapiBlobFlagsOffset:dpapiBlobMinHeader])&dpapiFlagLocalMachine != 0 {
		return fmt.Errorf("DPAPI blob is machine-scoped; only user-scoped agent state is accepted")
	}
	return nil
}
