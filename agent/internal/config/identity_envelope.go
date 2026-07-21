// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// The persisted identity is wrapped in a versioned envelope so the file
// declares how it is protected. On Windows the payload is DPAPI-encrypted
// under the service identity; elsewhere it is stored as-is with owner-only
// file permissions (protection scheme "none").
const (
	identityFormat        = "nodelink-agent-identity"
	identityFormatVersion = 1
)

// identityEnvelope is the on-disk wrapper around the protected identity bytes.
type identityEnvelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Protection string `json:"protection"`
	Data       string `json:"data"` // base64 of the protected identity JSON
}

// protector converts identity plaintext to/from its protected-at-rest form.
// Each platform supplies exactly one implementation (see protect_windows.go /
// protect_other.go); tests may substitute their own.
type protector interface {
	// Scheme names the protection this platform requires (e.g. "dpapi", "none").
	Scheme() string
	Protect(plaintext []byte) ([]byte, error)
	Unprotect(blob []byte) ([]byte, error)
}

// encodeIdentity serializes id into the protected envelope form.
func encodeIdentity(id *Identity, p protector) ([]byte, error) {
	plain, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	blob, err := p.Protect(plain)
	if err != nil {
		return nil, fmt.Errorf("protect identity (%s): %w", p.Scheme(), err)
	}
	return json.MarshalIndent(identityEnvelope{
		Format:     identityFormat,
		Version:    identityFormatVersion,
		Protection: p.Scheme(),
		Data:       base64.StdEncoding.EncodeToString(blob),
	}, "", "  ")
}

// decodeIdentity parses either the protected envelope form or the legacy
// plaintext identity JSON. It reports legacy=true when the input was an
// unprotected pre-envelope file, so the caller can migrate it. There is no
// other fallback: an envelope whose protection scheme does not match this
// platform's requirement fails closed rather than being read as plaintext.
func decodeIdentity(data []byte, p protector) (id *Identity, legacy bool, err error) {
	var env identityEnvelope
	if json.Unmarshal(data, &env) == nil && env.Format == identityFormat {
		if env.Version != identityFormatVersion {
			return nil, false, fmt.Errorf("identity envelope version %d is not supported by this agent build", env.Version)
		}
		if env.Protection != p.Scheme() {
			return nil, false, fmt.Errorf(
				"identity is protected with %q but this platform requires %q; delete the identity file and re-enroll",
				env.Protection, p.Scheme(),
			)
		}
		blob, decErr := base64.StdEncoding.DecodeString(env.Data)
		if decErr != nil {
			return nil, false, fmt.Errorf("identity envelope is corrupt: %w", decErr)
		}
		plain, unErr := p.Unprotect(blob)
		if unErr != nil {
			return nil, false, fmt.Errorf(
				"unprotect identity (%s): %w (identity may be corrupt or enrolled under a different account; delete the identity file and re-enroll)",
				p.Scheme(), unErr,
			)
		}
		var out Identity
		if jsonErr := json.Unmarshal(plain, &out); jsonErr != nil {
			return nil, false, fmt.Errorf("identity payload is corrupt: %w", jsonErr)
		}
		return &out, false, nil
	}

	// Legacy pre-envelope file: bare identity JSON. Accept it only if it looks
	// like a real identity; anything else is corruption, not a legacy file.
	var out Identity
	if jsonErr := json.Unmarshal(data, &out); jsonErr != nil {
		return nil, false, fmt.Errorf("parse identity: %w", jsonErr)
	}
	if out.AgentID == "" || out.AgentToken == "" {
		return nil, false, fmt.Errorf("identity file is not a recognized identity format")
	}
	return &out, true, nil
}
