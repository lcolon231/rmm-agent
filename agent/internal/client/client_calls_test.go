// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/inventory"
	"github.com/lcolon231/rmm/agent/internal/monitoring"
)

type seenRequest struct {
	method string
	path   string // RequestURI, including query
	auth   string
	ctype  string
	body   map[string]any
}

// recordingServer answers every request with status/body and records the last
// request it saw.
func recordingServer(t *testing.T, status int, respBody string) (*httptest.Server, *seenRequest) {
	t.Helper()
	seen := &seenRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.method = r.Method
		seen.path = r.RequestURI
		seen.auth = r.Header.Get("Authorization")
		seen.ctype = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		seen.body = nil
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &seen.body)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(srv.Close)
	return srv, seen
}

func TestStatusErrorAndIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"401", &StatusError{StatusCode: 401, Message: "m"}, true},
		{"wrapped 401", errors.Join(errors.New("x"), &StatusError{StatusCode: 401}), true},
		{"403", &StatusError{StatusCode: 403}, false},
		{"plain", errors.New("boom"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUnauthorized(tt.err); got != tt.want {
				t.Fatalf("IsUnauthorized = %v, want %v", got, tt.want)
			}
		})
	}
	if got := (&StatusError{StatusCode: 500, Message: "msg"}).Error(); got != "msg" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestSettersAffectRequests(t *testing.T) {
	srv, seen := recordingServer(t, 200, `{}`)
	c := New(srv.URL+"/", "")
	c.SetToken("tok-1")
	c.SetToken("tok-2")
	c.SetCapabilities([]string{"a", "b"})
	c.SetUpdateChannel("beta")
	if got := c.advertisedUpdateChannel(); got != "beta" {
		t.Fatalf("channel = %q", got)
	}
	if got := c.advertisedCapabilities(); len(got) != 2 || got[0] != "a" {
		t.Fatalf("capabilities = %v", got)
	}
	// advertisedCapabilities must return a copy.
	c.advertisedCapabilities()[0] = "mutated"
	if c.advertisedCapabilities()[0] != "a" {
		t.Fatal("capabilities slice aliased")
	}
	if err := c.ReportSelfUpdate(context.Background(), SelfUpdateOutcome{Status: "ok"}); err != nil {
		t.Fatal(err)
	}
	if seen.auth != "Bearer tok-2" {
		t.Fatalf("auth = %q", seen.auth)
	}
}

func TestAuthenticatedCalls(t *testing.T) {
	f := 1.5
	tests := []struct {
		name       string
		respBody   string
		call       func(c *Client) error
		wantMethod string
		wantPath   string
		wantBody   map[string]any
	}{
		{
			name:     "SubmitInventory",
			respBody: `{"ok":true,"stored_sections":["os"],"unchanged_sections":["hw"]}`,
			call: func(c *Client) error {
				ack, err := c.SubmitInventory(context.Background(), inventory.Submission{
					InventorySchemaVersion: 3, AgentVersion: "1.2.3",
				})
				if err == nil && (!ack.OK || len(ack.StoredSections) != 1 || ack.UnchangedSections[0] != "hw") {
					t.Errorf("ack = %+v", ack)
				}
				return err
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/me/inventory",
			wantBody:   map[string]any{"inventory_schema_version": float64(3), "agent_version": "1.2.3"},
		},
		{
			name:     "SubmitMonitoringResults",
			respBody: `{"ok":true,"accepted":2,"duplicates":1}`,
			call: func(c *Client) error {
				ack, err := c.SubmitMonitoringResults(context.Background(), []monitoring.Result{
					{ID: "r1", PolicyID: "p", CheckKey: "cpu", Status: "ok", Value: &f, EvaluatedAt: time.Unix(0, 0).UTC()},
				})
				if err == nil && (ack.Accepted != 2 || ack.Duplicates != 1) {
					t.Errorf("ack = %+v", ack)
				}
				return err
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/me/monitoring/results",
		},
		{
			name: "ReportSelfUpdate",
			call: func(c *Client) error {
				return c.ReportSelfUpdate(context.Background(), SelfUpdateOutcome{
					ReleaseID: "rel", Status: "healthy", Attempts: 2,
				})
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/me/self-update/report",
			wantBody:   map[string]any{"release_id": "rel", "status": "healthy", "attempts": float64(2)},
		},
		{
			name: "ReportResult",
			call: func(c *Client) error {
				return c.ReportResult(context.Background(), "cmd-1", CommandResult{ExitCode: 3, Stdout: "o"})
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/commands/cmd-1/result",
			wantBody:   map[string]any{"exit_code": float64(3), "stdout": "o", "stderr": ""},
		},
		{
			name:     "AttachShellSession",
			respBody: `{"session":{"id":"s1","status":"active"}}`,
			call: func(c *Client) error {
				s, err := c.AttachShellSession(context.Background())
				if err == nil && s.ID != "s1" {
					t.Errorf("session = %+v", s)
				}
				return err
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/me/shell-sessions/attach",
			wantBody:   map[string]any{},
		},
		{
			name:     "PollShellInput",
			respBody: `{"session":{"id":"a/b"},"frames":[{"seq":4,"stream":"stdin","data_b64":"aGk=","eof":false}]}`,
			call: func(c *Client) error {
				b, err := c.PollShellInput(context.Background(), "a/b", 3, 2)
				if err == nil && (len(b.Frames) != 1 || b.Frames[0].Seq != 4) {
					t.Errorf("batch = %+v", b)
				}
				return err
			},
			wantMethod: "GET",
			wantPath:   "/api/v1/agents/me/shell-sessions/a%2Fb/input?after=3&ack=2",
		},
		{
			name: "SendShellOutput",
			call: func(c *Client) error {
				return c.SendShellOutput(context.Background(), "s1", ShellFrame{Seq: 9, Stream: "stdout", DataBase64: "eA==", EOF: true})
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/me/shell-sessions/s1/output",
			wantBody:   map[string]any{"seq": float64(9), "stream": "stdout", "data_b64": "eA==", "eof": true},
		},
		{
			name: "CompleteShellSession",
			call: func(c *Client) error {
				return c.CompleteShellSession(context.Background(), "s1", "closed", "done")
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/me/shell-sessions/s1/complete",
			wantBody:   map[string]any{"status": "closed", "reason": "done"},
		},
		{
			name:     "RenewCredential",
			respBody: `{"agent_id":"a","agent_token":"new","credential_generation":2}`,
			call: func(c *Client) error {
				r, err := c.RenewCredential(context.Background(), "nonce-1")
				if err == nil && (r.AgentToken != "new" || r.CredentialGeneration != 2) {
					t.Errorf("resp = %+v", r)
				}
				return err
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/credentials/renew",
			wantBody:   map[string]any{"rotation_nonce": "nonce-1"},
		},
		{
			name:     "ReattachCredential",
			respBody: `{"agent_id":"a","agent_token":"re"}`,
			call: func(c *Client) error {
				r, err := c.ReattachCredential(context.Background(), "nonce-2")
				if err == nil && r.AgentToken != "re" {
					t.Errorf("resp = %+v", r)
				}
				return err
			},
			wantMethod: "POST",
			wantPath:   "/api/v1/agents/credentials/reattach",
			wantBody:   map[string]any{"rotation_nonce": "nonce-2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.respBody
			status := 200
			if body == "" {
				status = 204
			}
			srv, seen := recordingServer(t, status, body)
			c := New(srv.URL, "secret-token")
			if err := tt.call(c); err != nil {
				t.Fatal(err)
			}
			if seen.method != tt.wantMethod || seen.path != tt.wantPath {
				t.Fatalf("request = %s %s, want %s %s", seen.method, seen.path, tt.wantMethod, tt.wantPath)
			}
			if seen.auth != "Bearer secret-token" {
				t.Fatalf("Authorization = %q", seen.auth)
			}
			if seen.ctype != "application/json" {
				t.Fatalf("Content-Type = %q", seen.ctype)
			}
			for k, want := range tt.wantBody {
				if got, ok := seen.body[k]; !ok || got != want {
					t.Errorf("body[%q] = %v (present=%v), want %v", k, got, ok, want)
				}
			}
			if tt.wantBody != nil && len(tt.wantBody) == 0 && len(seen.body) != 0 {
				t.Errorf("body = %v, want empty object", seen.body)
			}
		})
	}
}

func TestMonitoringResultsBodyShape(t *testing.T) {
	srv, seen := recordingServer(t, 200, `{"ok":true}`)
	f := 2.0
	_, err := New(srv.URL, "t").SubmitMonitoringResults(context.Background(), []monitoring.Result{
		{ID: "r1", CheckKey: "cpu", Value: &f},
	})
	if err != nil {
		t.Fatal(err)
	}
	list, ok := seen.body["results"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("results = %v", seen.body["results"])
	}
	first := list[0].(map[string]any)
	if first["id"] != "r1" || first["check_key"] != "cpu" || first["value"] != 2.0 {
		t.Fatalf("result = %v", first)
	}
}

func TestAuthenticatedCallsErrorHandling(t *testing.T) {
	calls := map[string]func(c *Client) error{
		"SubmitInventory": func(c *Client) error {
			_, err := c.SubmitInventory(context.Background(), inventory.Submission{})
			return err
		},
		"SubmitMonitoringResults": func(c *Client) error {
			_, err := c.SubmitMonitoringResults(context.Background(), nil)
			return err
		},
		"ReportSelfUpdate": func(c *Client) error {
			return c.ReportSelfUpdate(context.Background(), SelfUpdateOutcome{})
		},
		"ReportResult": func(c *Client) error {
			return c.ReportResult(context.Background(), "c", CommandResult{})
		},
		"AttachShellSession": func(c *Client) error {
			_, err := c.AttachShellSession(context.Background())
			return err
		},
		"PollShellInput": func(c *Client) error {
			_, err := c.PollShellInput(context.Background(), "s", 0, 0)
			return err
		},
		"SendShellOutput": func(c *Client) error {
			return c.SendShellOutput(context.Background(), "s", ShellFrame{})
		},
		"CompleteShellSession": func(c *Client) error {
			return c.CompleteShellSession(context.Background(), "s", "x", "y")
		},
		"RenewCredential": func(c *Client) error {
			_, err := c.RenewCredential(context.Background(), "n")
			return err
		},
		"ReattachCredential": func(c *Client) error {
			_, err := c.ReattachCredential(context.Background(), "n")
			return err
		},
	}
	statuses := []int{400, 401, 403, 422, 500, 503}
	for name, call := range calls {
		for _, status := range statuses {
			t.Run(name, func(t *testing.T) {
				srv, _ := recordingServer(t, status, "nope Bearer abcdefghijklmnop.qrstuv")
				err := call(New(srv.URL, "tok"))
				var se *StatusError
				if !errors.As(err, &se) || se.StatusCode != status {
					t.Fatalf("status %d: err = %v", status, err)
				}
				if !strings.Contains(se.Message, "nope") {
					t.Fatalf("message lost body: %q", se.Message)
				}
				if IsUnauthorized(err) != (status == 401) {
					t.Fatalf("IsUnauthorized wrong for %d", status)
				}
			})
		}
		t.Run(name+"/empty token", func(t *testing.T) {
			srv, seen := recordingServer(t, 200, `{}`)
			err := call(New(srv.URL, ""))
			if err == nil || !strings.Contains(err.Error(), "agent token is empty") {
				t.Fatalf("err = %v", err)
			}
			if seen.method != "" {
				t.Fatal("request sent without a token")
			}
		})
		t.Run(name+"/unreachable", func(t *testing.T) {
			srv, _ := recordingServer(t, 200, `{}`)
			url := srv.URL
			srv.Close()
			if err := call(New(url, "tok")); err == nil {
				t.Fatal("expected transport error")
			}
		})
	}
}

func TestMalformedJSONResponseIsError(t *testing.T) {
	srv, _ := recordingServer(t, 200, `not json`)
	c := New(srv.URL, "tok")
	if _, err := c.SubmitInventory(context.Background(), inventory.Submission{}); err == nil {
		t.Fatal("expected decode error")
	}
	if _, err := c.PollShellInput(context.Background(), "s", 0, 0); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestOpenSupportChatNeverLeaksServerError(t *testing.T) {
	srv, _ := recordingServer(t, 500, "secret-chat-credential")
	_, err := New(srv.URL, "tok").OpenSupportChat(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-chat-credential") {
		t.Fatalf("err = %v", err)
	}
}

func TestCancelledContextFailsCalls(t *testing.T) {
	srv, seen := recordingServer(t, 200, `{}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(srv.URL, "tok").ReportSelfUpdate(ctx, SelfUpdateOutcome{}); err == nil {
		t.Fatal("expected context error")
	}
	if seen.method != "" {
		t.Fatal("request sent despite cancelled context")
	}
}

func TestInvalidMethodFailsRequestConstruction(t *testing.T) {
	c := New("http://127.0.0.1:1", "tok")
	if err := c.do(context.Background(), "BAD METHOD", "/x", nil, nil, true); err == nil {
		t.Fatal("expected request construction error")
	}
}

func TestUnmarshalableBodyFails(t *testing.T) {
	c := New("http://127.0.0.1:1", "tok")
	if err := c.do(context.Background(), "POST", "/x", make(chan int), nil, true); err == nil {
		t.Fatal("expected marshal error")
	}
}
