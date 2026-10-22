// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

// fakeServer counts hits per path and answers with a configurable status.
type fakeServer struct {
	mu     sync.Mutex
	status int
	body   string
	hits   map[string]int
	srv    *httptest.Server
}

func newFakeServer(t *testing.T, status int, body string) *fakeServer {
	t.Helper()
	f := &fakeServer{status: status, body: body, hits: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.hits[r.URL.Path]++
		status, body := f.status, f.body
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) set(status int, body string) {
	f.mu.Lock()
	f.status, f.body = status, body
	f.mu.Unlock()
}

func (f *fakeServer) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

const okAck = `{"ok":true,"pending_commands":[],"command_public_keys":{}}`

// routedClient builds a client whose origin and relays all trust the test TLS
// servers' certificates.
func routedClient(t *testing.T, origin *fakeServer, relays ...*fakeServer) *Client {
	t.Helper()
	c := New(origin.srv.URL, "agent-token")
	c.http = origin.srv.Client()
	routes := make([]Route, 0, len(relays))
	for i, relay := range relays {
		routes = append(routes, Route{ID: string(rune('a' + i)), BaseURL: relay.srv.URL})
	}
	if err := c.SetRoutes(routes, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i, relay := range relays {
		c.routes[i].http = relay.srv.Client()
	}
	return c
}

func beat(t *testing.T, c *Client) error {
	t.Helper()
	_, err := c.Heartbeat(context.Background(), telemetry.Sample{}, nil)
	return err
}

func TestRoutedCallsPreferFirstHealthyRelay(t *testing.T) {
	origin := newFakeServer(t, 200, okAck)
	first := newFakeServer(t, 200, okAck)
	second := newFakeServer(t, 200, okAck)
	c := routedClient(t, origin, first, second)
	if err := beat(t, c); err != nil {
		t.Fatal(err)
	}
	if first.count("/api/v1/heartbeat") != 1 || second.count("/api/v1/heartbeat") != 0 ||
		origin.count("/api/v1/heartbeat") != 0 {
		t.Fatalf("unexpected routing: first=%d second=%d origin=%d",
			first.count("/api/v1/heartbeat"), second.count("/api/v1/heartbeat"), origin.count("/api/v1/heartbeat"))
	}
	if c.LastRoute() != "a" {
		t.Fatalf("LastRoute = %q", c.LastRoute())
	}
}

func TestPartitionFailsOverThenCoolsDownThenRecovers(t *testing.T) {
	origin := newFakeServer(t, 200, okAck)
	first := newFakeServer(t, 503, `{"detail":"upstream down"}`)
	second := newFakeServer(t, 403, `{"detail":{"code":"relay_region_mismatch"}}`)
	c := routedClient(t, origin, first, second)

	if err := beat(t, c); err != nil {
		t.Fatal(err)
	}
	if origin.count("/api/v1/heartbeat") != 1 || c.LastRoute() != OriginRouteID {
		t.Fatalf("expected origin fallback, last=%q", c.LastRoute())
	}
	// Both relays are now cooling down: the next beat goes straight to origin.
	if err := beat(t, c); err != nil {
		t.Fatal(err)
	}
	if first.count("/api/v1/heartbeat") != 1 || second.count("/api/v1/heartbeat") != 1 {
		t.Fatal("a cooling-down relay was retried")
	}
	// After the partition heals and the cooldown lapses the relay is used again.
	first.set(200, okAck)
	c.mu.Lock()
	c.routes[0].until = time.Time{}
	c.mu.Unlock()
	if err := beat(t, c); err != nil {
		t.Fatal(err)
	}
	if c.LastRoute() != "a" {
		t.Fatalf("expected recovery onto relay a, got %q", c.LastRoute())
	}
}

func TestUnauthorizedDoesNotFailOver(t *testing.T) {
	origin := newFakeServer(t, 200, okAck)
	relay := newFakeServer(t, 401, `{"detail":"Invalid agent token"}`)
	c := routedClient(t, origin, relay)
	err := beat(t, c)
	if !IsUnauthorized(err) {
		t.Fatalf("err = %v, want 401", err)
	}
	if origin.count("/api/v1/heartbeat") != 0 {
		t.Fatal("a credential refusal was retried through another route")
	}
}

func TestOrdinaryRequestErrorDoesNotFailOver(t *testing.T) {
	origin := newFakeServer(t, 200, okAck)
	relay := newFakeServer(t, 422, `{"detail":"bad body"}`)
	c := routedClient(t, origin, relay)
	if err := beat(t, c); err == nil || !strings.Contains(err.Error(), "422") {
		t.Fatalf("err = %v, want 422", err)
	}
	if origin.count("/api/v1/heartbeat") != 0 {
		t.Fatal("a request-level refusal was retried through another route")
	}
}

func TestExpiredRoutesFallBackToOriginPolling(t *testing.T) {
	origin := newFakeServer(t, 200, okAck)
	relay := newFakeServer(t, 200, okAck)
	c := routedClient(t, origin, relay)
	c.mu.Lock()
	c.routesExpireAt = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if err := beat(t, c); err != nil {
		t.Fatal(err)
	}
	if relay.count("/api/v1/heartbeat") != 0 || origin.count("/api/v1/heartbeat") != 1 {
		t.Fatal("an expired manifest's relay was used")
	}
}

func TestNonRelayableCallsAlwaysUseOrigin(t *testing.T) {
	origin := newFakeServer(t, 200, `{"url":"https://chat.example/x"}`)
	relay := newFakeServer(t, 200, `{"url":"https://evil.example/x"}`)
	c := routedClient(t, origin, relay)
	if _, err := c.OpenSupportChat(context.Background()); err != nil {
		t.Fatal(err)
	}
	if relay.count("/api/v1/support/agent/conversations") != 0 {
		t.Fatal("support chat was routed through a relay")
	}
}

func TestSetRoutesKeepsCooldownAcrossRefresh(t *testing.T) {
	origin := newFakeServer(t, 200, okAck)
	relay := newFakeServer(t, 503, `{}`)
	c := routedClient(t, origin, relay)
	if err := beat(t, c); err != nil {
		t.Fatal(err)
	}
	if err := c.SetRoutes([]Route{{ID: "a", BaseURL: relay.srv.URL}}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	c.mu.RLock()
	until := c.routes[0].until
	c.mu.RUnlock()
	if !until.After(time.Now()) {
		t.Fatal("a manifest refresh reset a failing relay's cooldown")
	}
}

func TestShouldFailoverClassification(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&StatusError{StatusCode: 502}, true},
		{&StatusError{StatusCode: 429}, true},
		{&StatusError{StatusCode: 401}, false},
		{&StatusError{StatusCode: 404, Message: `{"detail":"Not Found"}`}, false},
		{&StatusError{StatusCode: 409, Message: `POST /x: 409 {"detail":{"code":"relay_replay"}}`}, true},
		{&StatusError{StatusCode: 403, Message: `POST /x: 403 {"detail":{"code":"residency_route_required"}}`}, true},
		{context.Canceled, false},
		{errTransport{}, true},
	}
	for _, tc := range cases {
		if got := shouldFailover(tc.err); got != tc.want {
			t.Fatalf("shouldFailover(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

type errTransport struct{}

func (errTransport) Error() string { return "dial tcp: connection refused" }
