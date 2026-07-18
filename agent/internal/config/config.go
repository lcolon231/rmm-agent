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
}

// Identity is what the agent persists after a successful enrollment. It is
// written to disk with owner-only permissions.
type Identity struct {
	AgentID          string `json:"agent_id"`
	AgentToken       string `json:"agent_token"`
	CommandPublicKey string `json:"command_public_key"` // PEM Ed25519
	HeartbeatSeconds int    `json:"heartbeat_seconds"`
	ServerURL        string `json:"server_url"`
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

// LoadIdentity reads a previously persisted identity, if any.
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err // caller distinguishes os.IsNotExist
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	return &id, nil
}

// Save writes the identity with restrictive permissions (0600).
func (id *Identity) Save(path string) error {
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
