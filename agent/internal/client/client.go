// SPDX-License-Identifier: AGPL-3.0-only
// Package client is the agent's HTTP interface to the RMM server.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/protocol"
	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

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

// EnrollResponse mirrors the server schema.
type EnrollResponse struct {
	AgentID                string `json:"agent_id"`
	AgentToken             string `json:"agent_token"`
	HeartbeatSeconds       int    `json:"heartbeat_interval_seconds"`
	CommandPublicKey       string `json:"command_public_key"`
	CommandEnvelopeVersion string `json:"command_envelope_version"`
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
	if out.CommandEnvelopeVersion != protocol.CommandEnvelopeV1 {
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
	Signature       string          `json:"signature"`
	Status          string          `json:"status"`
	// ExpiresAt is the server-set TTL deadline (Python isoformat UTC). It is kept
	// as a raw string and parsed defensively in the runner so one malformed
	// timestamp cannot break decoding of the whole heartbeat ack. Empty/absent
	// means "no TTL". Note this field is NOT part of the signed canonical bytes;
	// the agent-side TTL check is defense-in-depth (see runner.processCommand).
	ExpiresAt string `json:"expires_at"`
}

// HeartbeatAck is the server's response to a heartbeat.
type HeartbeatAck struct {
	OK              bool      `json:"ok"`
	PendingCommands []Command `json:"pending_commands"`
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

// CommandResult is what the agent reports after execution.
type CommandResult struct {
	ExitCode int    `json:"exit_code"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
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
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
