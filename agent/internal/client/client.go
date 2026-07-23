// SPDX-License-Identifier: AGPL-3.0-only
// Package client is the agent's HTTP interface to the RMM server.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/protocol"
	"github.com/lcolon231/rmm/agent/internal/redact"
	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

// StatusError is an HTTP-level rejection from the server. Keeping the status
// code typed lets the runtime distinguish "server is unreachable" from "server
// answered and refused" (e.g. 401 after credential revocation).
type StatusError struct {
	StatusCode int
	Message    string
}

func (e *StatusError) Error() string { return e.Message }

// IsUnauthorized reports whether err is a definitive credential rejection.
func IsUnauthorized(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.StatusCode == http.StatusUnauthorized
}

// Client talks to the RMM server API.
type Client struct {
	baseURL    string
	agentToken string
	http       *http.Client
}

// New creates a client. agentToken may be empty for the enrollment call.
func New(baseURL, agentToken string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		agentToken: agentToken,
		http:       &http.Client{Timeout: 30 * time.Second},
	}
}

// NewWithTLSSPKIPins creates a client that performs normal PKI validation and
// additionally requires the leaf certificate's SPKI SHA-256 to match one of
// tlsSPKIPins. Pins use the conventional "sha256/<base64>" form. An empty
// slice preserves the ordinary Go/OS TLS behavior.
func NewWithTLSSPKIPins(baseURL, agentToken string, tlsSPKIPins []string) (*Client, error) {
	return newWithTLSConfig(baseURL, agentToken, tlsSPKIPins, nil)
}

func newWithTLSConfig(baseURL, agentToken string, pinStrings []string, tlsConfig *tls.Config) (*Client, error) {
	pins, err := parseSPKIPins(pinStrings)
	if err != nil {
		return nil, err
	}

	defaultTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("default HTTP transport does not support TLS pinning")
	}
	transport := defaultTransport.Clone()
	if len(pins) > 0 {
		parsedURL, parseErr := url.Parse(baseURL)
		if parseErr != nil || !strings.EqualFold(parsedURL.Scheme, "https") || parsedURL.Host == "" {
			return nil, fmt.Errorf("tls_spki_pins require a valid https server_url")
		}
	}
	if tlsConfig != nil {
		transport.TLSClientConfig = tlsConfig.Clone()
	} else if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	if len(pins) > 0 {
		if transport.TLSClientConfig.InsecureSkipVerify {
			return nil, fmt.Errorf("tls_spki_pins cannot be used with InsecureSkipVerify")
		}
		previousVerify := transport.TLSClientConfig.VerifyConnection
		transport.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
			// VerifyConnection runs after Go's standard chain and hostname checks
			// because InsecureSkipVerify remains false. Preserve any callback a
			// supplied TLS config already had before applying the additional pin.
			if previousVerify != nil {
				if verifyErr := previousVerify(state); verifyErr != nil {
					return verifyErr
				}
			}
			return verifyLeafSPKI(state, pins)
		}
	}

	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		agentToken: agentToken,
		http:       &http.Client{Timeout: 30 * time.Second, Transport: transport},
	}, nil
}

func parseSPKIPins(values []string) ([][]byte, error) {
	if len(values) == 0 {
		return nil, nil
	}
	pins := make([][]byte, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for i, value := range values {
		if !strings.HasPrefix(value, "sha256/") {
			return nil, fmt.Errorf("tls_spki_pins[%d]: expected sha256/<base64>", i)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "sha256/"))
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("tls_spki_pins[%d]: expected base64 of a 32-byte SHA-256 digest", i)
		}
		key := string(decoded)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		pins = append(pins, decoded)
	}
	return pins, nil
}

func verifyLeafSPKI(state tls.ConnectionState, pins [][]byte) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("tls SPKI pin verification: server supplied no certificate")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
	for _, pin := range pins {
		if subtle.ConstantTimeCompare(digest[:], pin) == 1 {
			return nil
		}
	}
	return fmt.Errorf(
		"tls SPKI pin mismatch (observed sha256/%s)",
		base64.StdEncoding.EncodeToString(digest[:]),
	)
}

// EnrollResponse mirrors the server schema.
type EnrollResponse struct {
	AgentID                string            `json:"agent_id"`
	AgentToken             string            `json:"agent_token"`
	HeartbeatSeconds       int               `json:"heartbeat_interval_seconds"`
	CommandPublicKey       string            `json:"command_public_key"`
	CommandPublicKeys      map[string]string `json:"command_public_keys"`
	CommandSigningKeyID    string            `json:"command_signing_key_id"`
	CommandEnvelopeVersion string            `json:"command_envelope_version"`
}

// Enroll claims an identity using a one-time enrollment token.
func (c *Client) Enroll(ctx context.Context, token string, host telemetry.HostInfo, agentVersion string) (*EnrollResponse, error) {
	body := map[string]any{
		"enrollment_token":                    token,
		"hostname":                            host.Hostname,
		"os":                                  host.OS,
		"os_version":                          host.OSVersion,
		"agent_version":                       agentVersion,
		"supported_command_envelope_versions": protocol.SupportedCommandEnvelopeVersions(),
	}
	var out EnrollResponse
	if err := c.do(ctx, "POST", "/api/v1/enroll", body, &out, false); err != nil {
		return nil, err
	}
	if out.CommandEnvelopeVersion != protocol.CommandEnvelopeV2 && out.CommandEnvelopeVersion != protocol.CommandEnvelopeV3 {
		return nil, fmt.Errorf(
			"server selected unsupported command envelope version %q",
			out.CommandEnvelopeVersion,
		)
	}
	return &out, nil
}

// Command mirrors the server's CommandOut schema.
type Command struct {
	ID              string          `json:"id"`
	AgentID         string          `json:"agent_id"`
	Kind            string          `json:"kind"`
	Payload         json.RawMessage `json:"payload"`
	EnvelopeVersion string          `json:"envelope_version"`
	SchemaVersion   int             `json:"schema_version"`
	IssuedAt        string          `json:"issued_at"`
	Nonce           string          `json:"nonce"`
	SigningKeyID    string          `json:"signing_key_id"`
	Signature       string          `json:"signature"`
	Status          string          `json:"status"`
	// ExpiresAt is the server-set TTL deadline (Python isoformat UTC). It is kept
	// as a raw string and parsed defensively in the runner so one malformed
	// timestamp cannot break decoding of the whole heartbeat ack. Empty/absent
	// means "no TTL" for legacy responses. command-v2 requires this field and
	// binds its exact canonical value into the signature.
	ExpiresAt string `json:"expires_at"`
}

// Trust states the server may report in a heartbeat ack. An empty string (an
// older server) means active.
const (
	TrustStateActive      = "active"
	TrustStateQuarantined = "quarantined"
)

// HeartbeatAck is the server's response to a heartbeat.
type HeartbeatAck struct {
	OK                bool              `json:"ok"`
	PendingCommands   []Command         `json:"pending_commands"`
	CommandPublicKeys map[string]string `json:"command_public_keys"`
	// TrustState reports how the server currently trusts this agent. When it is
	// "quarantined" the agent must not execute anything, even if commands were
	// somehow present in the ack.
	TrustState string `json:"trust_state"`
}

// Heartbeat posts telemetry and returns any queued commands. inventory may be
// nil for ordinary beats.
func (c *Client) Heartbeat(ctx context.Context, s telemetry.Sample, inventory map[string]any) (*HeartbeatAck, error) {
	body := map[string]any{
		"cpu_percent":                         s.CPUPercent,
		"mem_percent":                         s.MemPercent,
		"disk_percent":                        s.DiskPercent,
		"uptime_seconds":                      s.UptimeSeconds,
		"logged_in_user":                      s.LoggedInUser,
		"supported_command_envelope_versions": protocol.SupportedCommandEnvelopeVersions(),
	}
	if inventory != nil {
		body["inventory"] = inventory
	}
	var ack HeartbeatAck
	if err := c.do(ctx, "POST", "/api/v1/heartbeat", body, &ack, true); err != nil {
		return nil, err
	}
	return &ack, nil
}

// CommandResult is what the agent reports after execution. The truncation
// fields are additive: an older server ignores them.
type CommandResult struct {
	ExitCode         int    `json:"exit_code"`
	Stdout           string `json:"stdout"`
	Stderr           string `json:"stderr"`
	StdoutTruncated  bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated  bool   `json:"stderr_truncated,omitempty"`
	StdoutTotalBytes int64  `json:"stdout_total_bytes,omitempty"`
	StderrTotalBytes int64  `json:"stderr_total_bytes,omitempty"`
}

// ReportResult sends the outcome of a command back to the server.
func (c *Client) ReportResult(ctx context.Context, commandID string, r CommandResult) error {
	path := fmt.Sprintf("/api/v1/commands/%s/result", commandID)
	return c.do(ctx, "POST", path, r, nil, true)
}

// do performs a JSON request. If auth is true, the agent bearer token is sent.
func (c *Client) do(ctx context.Context, method, path string, in, out any, auth bool) error {
	var reader io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if auth {
		if c.agentToken == "" {
			return fmt.Errorf("auth required but agent token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+c.agentToken)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		// The server error body is untrusted free text that gets logged; scrub
		// any credential-shaped substrings before it enters an error message.
		return &StatusError{
			StatusCode: resp.StatusCode,
			Message: redact.Text(fmt.Sprintf(
				"%s %s: %d %s", method, path, resp.StatusCode,
				strings.TrimSpace(string(b)))),
		}
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
