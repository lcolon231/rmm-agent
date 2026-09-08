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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lcolon231/rmm/agent/internal/inventory"
	"github.com/lcolon231/rmm/agent/internal/monitoring"
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
	mu         sync.RWMutex
	baseURL    string
	agentToken string
	// agentVersion is the running build's version, reported on every
	// authenticated heartbeat so the server can refresh a stale stored value
	// after an in-place upgrade without a re-enrollment (issue #179). Empty
	// until SetAgentVersion is called; the field is then omitted from the beat.
	agentVersion string
	// capabilities is the advertised optional-feature set. Empty until
	// SetCapabilities is called, in which case the default set is advertised;
	// this lets the runtime add config-gated capabilities (e.g. Chocolatey)
	// without threading config through every call site.
	capabilities []string
	// updateChannel is the release channel this endpoint follows (issue #63).
	// Empty means the endpoint follows the default stable channel and the field
	// is omitted, which an older server ignores.
	updateChannel string
	http          *http.Client
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
	CredentialExpiresAt    string            `json:"credential_expires_at"`
}

// Enroll claims an identity using a one-time enrollment token.
func (c *Client) Enroll(ctx context.Context, token string, host telemetry.HostInfo, agentVersion string) (*EnrollResponse, error) {
	return c.EnrollWithName(ctx, token, "", host, agentVersion)
}

// EnrollWithName claims an identity and optionally supplies an administrator-
// recognizable agent name. The token is serialized only into the HTTPS request
// body and is never placed in a URL or log by this package.
func (c *Client) EnrollWithName(ctx context.Context, token, agentName string, host telemetry.HostInfo, agentVersion string) (*EnrollResponse, error) {
	body := map[string]any{
		"enrollment_token":                    token,
		"agent_name":                          agentName,
		"hostname":                            host.Hostname,
		"os":                                  host.OS,
		"os_version":                          host.OSVersion,
		"agent_version":                       agentVersion,
		"architecture":                        runtime.GOARCH,
		"supported_command_envelope_versions": protocol.SupportedCommandEnvelopeVersions(),
		"supported_capabilities":              c.advertisedCapabilities(),
	}
	if channel := c.advertisedUpdateChannel(); channel != "" {
		body["update_channel"] = channel
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

// SetToken switches the bearer credential used for authenticated requests. The
// client is driven by the single check-in goroutine, so this needs no locking.
// Used after a successful credential renewal to adopt the rotated token.
func (c *Client) SetToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agentToken = token
}

// SetAgentVersion records the running build's version so every subsequent
// heartbeat reports it. Called once when the check-in session is built; like
// SetToken it needs no locking because a single goroutine drives the client.
func (c *Client) SetAgentVersion(agentVersion string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.agentVersion = agentVersion
}

// SetCapabilities overrides the advertised optional-feature set for enroll and
// heartbeat. The runtime uses this to include config-gated capabilities such as
// the opt-in Chocolatey provider. Like SetToken it needs no locking because a
// single goroutine drives the client.
func (c *Client) SetCapabilities(capabilities []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.capabilities = append([]string(nil), capabilities...)
}

// SetUpdateChannel records the release channel this endpoint follows so the
// server only ever targets it with a release published on that channel. An
// empty value means the default (stable) and is not sent.
func (c *Client) SetUpdateChannel(channel string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateChannel = channel
}

func (c *Client) advertisedUpdateChannel() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.updateChannel
}

// advertisedCapabilities returns the configured capability set, or the default
// set when SetCapabilities was never called (e.g. a bare client in a test).
func (c *Client) advertisedCapabilities() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.capabilities != nil {
		return append([]string(nil), c.capabilities...)
	}
	return protocol.SupportedCapabilities()
}

// ShellSession is the payload shared by the lifecycle and framed-I/O APIs.
type ShellSession struct {
	ID               string `json:"id"`
	AgentID          string `json:"agent_id"`
	Status           string `json:"status"`
	CloseReason      string `json:"close_reason"`
	ClientLastSeq    int64  `json:"client_last_seq,omitempty"`
	AgentLastSeq     int64  `json:"agent_last_seq,omitempty"`
	OutputBytesLimit int64  `json:"output_bytes_limit"`
}

type ShellFrame struct {
	Seq        int64  `json:"seq"`
	Stream     string `json:"stream"`
	DataBase64 string `json:"data_b64"`
	EOF        bool   `json:"eof"`
	ByteLength int    `json:"byte_length,omitempty"`
}

type ShellFrameBatch struct {
	Session ShellSession `json:"session"`
	Frames  []ShellFrame `json:"frames"`
}

func (c *Client) AttachShellSession(ctx context.Context) (*ShellSession, error) {
	var out struct {
		Session *ShellSession `json:"session"`
	}
	if err := c.do(ctx, "POST", "/api/v1/agents/me/shell-sessions/attach", map[string]any{}, &out, true); err != nil {
		return nil, err
	}
	return out.Session, nil
}

func (c *Client) PollShellInput(ctx context.Context, sessionID string, after, ack int64) (*ShellFrameBatch, error) {
	path := fmt.Sprintf("/api/v1/agents/me/shell-sessions/%s/input?after=%d&ack=%d", url.PathEscape(sessionID), after, ack)
	var out ShellFrameBatch
	if err := c.do(ctx, "GET", path, nil, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SendShellOutput(ctx context.Context, sessionID string, frame ShellFrame) error {
	path := fmt.Sprintf("/api/v1/agents/me/shell-sessions/%s/output", url.PathEscape(sessionID))
	return c.do(ctx, "POST", path, frame, nil, true)
}

func (c *Client) CompleteShellSession(ctx context.Context, sessionID, state, reason string) error {
	path := fmt.Sprintf("/api/v1/agents/me/shell-sessions/%s/complete", url.PathEscape(sessionID))
	body := map[string]any{"status": state, "reason": reason}
	return c.do(ctx, "POST", path, body, nil, true)
}

// AgentCredentialRenewResponse mirrors the server schema (issue #125).
type AgentCredentialRenewResponse struct {
	AgentID              string `json:"agent_id"`
	AgentToken           string `json:"agent_token"`
	CredentialExpiresAt  string `json:"credential_expires_at"`
	OverlapExpiresAt     string `json:"overlap_expires_at"`
	CredentialGeneration int    `json:"credential_generation"`
}

// RenewCredential rotates the agent's bearer credential. The nonce is a fresh,
// per-attempt value the server records to reject a verbatim replay; a genuine
// retry after a lost response uses a new nonce and rotates against the still-
// valid overlap credential. Proof of possession is the current bearer, so this
// is an authenticated call.
func (c *Client) RenewCredential(ctx context.Context, rotationNonce string) (*AgentCredentialRenewResponse, error) {
	var out AgentCredentialRenewResponse
	body := map[string]any{"rotation_nonce": rotationNonce}
	if err := c.do(ctx, "POST", "/api/v1/agents/credentials/renew", body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReattachCredential replaces a recently expired bearer through the server's
// bounded recovery path. Refused credentials always receive the same 401, so
// callers cannot distinguish revoked, quarantined, unknown, or too-old state.
func (c *Client) ReattachCredential(ctx context.Context, rotationNonce string) (*AgentCredentialRenewResponse, error) {
	var out AgentCredentialRenewResponse
	body := map[string]any{"rotation_nonce": rotationNonce}
	if err := c.do(ctx, "POST", "/api/v1/agents/credentials/reattach", body, &out, true); err != nil {
		return nil, err
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
	// InventoryRequested names the inventory sections whose stored copy the
	// server considers missing, changed, or stale. Empty on a steady-state
	// beat, which is the common case. An older server omits it entirely.
	InventoryRequested []string `json:"inventory_requested"`
	// MonitoringChecks is the current revision-pinned effective policy. Older
	// servers omit it, which safely evaluates nothing.
	MonitoringChecks []monitoring.Assignment `json:"monitoring_checks"`
}

// PendingResultNotice tells the server that execution has finished locally but
// the durable result has not yet been acknowledged. This makes the delivery
// gap operator-visible without copying command output into heartbeat data.
type PendingResultNotice struct {
	CommandID        string `json:"command_id"`
	AgentCompletedAt string `json:"agent_completed_at,omitempty"`
}

// Heartbeat posts telemetry and returns any queued commands. inventoryHashes
// may be nil when the agent has nothing collected yet.
func (c *Client) Heartbeat(ctx context.Context, s telemetry.Sample, inventoryHashes map[string]string) (*HeartbeatAck, error) {
	return c.HeartbeatWithPendingResults(ctx, s, inventoryHashes, nil)
}

// HeartbeatWithPendingResults is Heartbeat plus a bounded list of durable
// outbox entries waiting for idempotent result acknowledgement.
func (c *Client) HeartbeatWithPendingResults(
	ctx context.Context,
	s telemetry.Sample,
	inventoryHashes map[string]string,
	pendingResults []PendingResultNotice,
) (*HeartbeatAck, error) {
	body := map[string]any{
		"cpu_percent":                         s.CPUPercent,
		"mem_percent":                         s.MemPercent,
		"disk_percent":                        s.DiskPercent,
		"uptime_seconds":                      s.UptimeSeconds,
		"logged_in_user":                      s.LoggedInUser,
		"supported_command_envelope_versions": protocol.SupportedCommandEnvelopeVersions(),
		"supported_capabilities":              c.advertisedCapabilities(),
		"pending_results":                     pendingResults,
	}
	// The running build's version rides on every beat so an in-place upgrade
	// refreshes the server's stored value on the next successful check-in
	// rather than waiting for a re-enrollment or an inventory change. The
	// server rejects an empty value, so an unset version is omitted instead of
	// sent blank — that only happens in tests that build a bare client.
	c.mu.RLock()
	agentVersion := c.agentVersion
	c.mu.RUnlock()
	if agentVersion != "" {
		body["agent_version"] = agentVersion
	}
	// Additive like the version: an older server ignores it, and omitting it
	// leaves the server's stored channel untouched rather than resetting it.
	if channel := c.advertisedUpdateChannel(); channel != "" {
		body["update_channel"] = channel
	}
	// Only digests ride on the beat. Full snapshots go to SubmitInventory when
	// the server asks, so heartbeat size stays independent of how much hardware
	// an endpoint has.
	if len(inventoryHashes) > 0 {
		body["inventory_hashes"] = inventoryHashes
	}
	var ack HeartbeatAck
	if err := c.do(ctx, "POST", "/api/v1/heartbeat", body, &ack, true); err != nil {
		return nil, err
	}
	return &ack, nil
}

// InventoryAck reports what the server did with each submitted section.
type InventoryAck struct {
	OK                bool     `json:"ok"`
	StoredSections    []string `json:"stored_sections"`
	UnchangedSections []string `json:"unchanged_sections"`
}

// SubmitInventory uploads the sections the server asked for. The server bounds
// and validates every section and rejects the whole submission rather than
// storing a truncated one, so a rejection here means the agent and server
// disagree about the contract — not that some data was quietly dropped.
func (c *Client) SubmitInventory(ctx context.Context, s inventory.Submission) (*InventoryAck, error) {
	var ack InventoryAck
	if err := c.do(ctx, "POST", "/api/v1/agents/me/inventory", s, &ack, true); err != nil {
		return nil, err
	}
	return &ack, nil
}

// SubmitMonitoringResults uploads one durable, bounded result batch. The
// server validates the policy revision and treats repeated result IDs as
// successful duplicates.
func (c *Client) SubmitMonitoringResults(ctx context.Context, results []monitoring.Result) (*monitoring.ResultAck, error) {
	var ack monitoring.ResultAck
	body := map[string]any{"results": results}
	if err := c.do(ctx, "POST", "/api/v1/agents/me/monitoring/results", body, &ack, true); err != nil {
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
	AgentCompletedAt string `json:"agent_completed_at,omitempty"`
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

// SelfUpdateOutcome is the post-restart resolution of a staged self-update
// (issue #63). It is reported separately from the command result because the
// deciding evidence — did the new build come up healthy — only exists after the
// restart, by which time the command that staged it has already completed.
type SelfUpdateOutcome struct {
	ReleaseID       string `json:"release_id,omitempty"`
	CommandID       string `json:"command_id,omitempty"`
	FromVersion     string `json:"from_version,omitempty"`
	ToVersion       string `json:"to_version,omitempty"`
	ObservedVersion string `json:"observed_version,omitempty"`
	Status          string `json:"status"`
	Reason          string `json:"reason,omitempty"`
	Attempts        int    `json:"attempts,omitempty"`
}

// ReportSelfUpdate submits a resolved self-update attempt. The server records
// the evidence and feeds it into the staged rollout's halt rule.
func (c *Client) ReportSelfUpdate(ctx context.Context, outcome SelfUpdateOutcome) error {
	return c.do(ctx, "POST", "/api/v1/agents/me/self-update/report", outcome, nil, true)
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
		c.mu.RLock()
		token := c.agentToken
		c.mu.RUnlock()
		if token == "" {
			return fmt.Errorf("auth required but agent token is empty")
		}
		req.Header.Set("Authorization", "Bearer "+token)
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
