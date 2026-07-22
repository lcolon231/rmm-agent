// SPDX-License-Identifier: AGPL-3.0-only
// Package config handles agent configuration and the persisted identity that
// results from enrollment.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config is the static configuration an operator provides at install time.
type Config struct {
	// ServerURL is the base URL of the RMM server, e.g. https://rmm.nodelink.example
	ServerURL string `json:"server_url"`
	// EnrollmentToken is the one-time token used on first run. Cleared from
	// the persisted identity once enrollment succeeds.
	EnrollmentToken string `json:"enrollment_token,omitempty"`
	// HeartbeatSeconds may be overridden locally; otherwise the server value
	// received at enrollment is used.
	HeartbeatSeconds int `json:"heartbeat_seconds,omitempty"`
	// TLSSPKIPins optionally adds an SPKI pin requirement after normal TLS
	// chain and hostname verification. Multiple pins support key rotation.
	TLSSPKIPins []string `json:"tls_spki_pins,omitempty"`
}

// Identity is what the agent persists after a successful enrollment. It is
// written to disk with owner-only permissions.
type Identity struct {
	AgentID             string            `json:"agent_id"`
	AgentToken          string            `json:"agent_token"`
	CommandPublicKey    string            `json:"command_public_key"` // PEM Ed25519
	CommandPublicKeys   map[string]string `json:"command_public_keys,omitempty"`
	CommandSigningKeyID string            `json:"command_signing_key_id,omitempty"`
	HeartbeatSeconds    int               `json:"heartbeat_seconds"`
	ServerURL           string            `json:"server_url"`
}

// Load reads the install-time config from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.ServerURL == "" {
		return nil, fmt.Errorf("config: server_url is required")
	}
	return &c, nil
}

// IdentityPath returns where the enrolled identity is stored, alongside the
// config file by convention.
func IdentityPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "identity.json")
}

// LoadIdentity reads a previously persisted identity, if any. A legacy
// plaintext identity file is migrated in place to the protected envelope form;
// if the migration cannot be persisted, loading fails rather than continuing
// to operate from a plaintext credential on disk.
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // caller distinguishes os.IsNotExist
	}
	id, legacy, err := decodeIdentity(data, platformProtector)
	if err != nil {
		return nil, err
	}
	if legacy {
		if err := id.Save(path); err != nil {
			return nil, fmt.Errorf("migrate plaintext identity to protected form: %w", err)
		}
	}
	return id, nil
}

// Save writes the identity in its protected envelope form: protected via the
// platform protector (DPAPI on Windows), written atomically with restrictive
// permissions, then locked down further with a platform ACL where applicable.
// There is no plaintext fallback — if protection fails, nothing is written.
func (id *Identity) Save(path string) error {
	data, err := encodeIdentity(id, platformProtector)
	if err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write can never leave a truncated or
	// half-plaintext identity behind, and the previous file is fully replaced
	// (a plaintext predecessor is not left beside the protected copy).
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return applyIdentityACL(path)
}
