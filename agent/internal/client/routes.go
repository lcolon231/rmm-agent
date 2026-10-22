// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Relay routing (issue #87). An agent may reach the control plane through
// regional relays named in a server-signed routing manifest. Only the polling
// endpoints a relay is allowed to carry are routed; everything else
// (enrollment, credential reattach, shell, chat, self-update) always uses the
// enrolled origin. The origin is the final fallback for every routed call, so
// polling keeps working when every relay is down or the manifest has lapsed.

// OriginRouteID identifies the enrolled server URL in route reports.
const OriginRouteID = "origin"

const (
	routeCooldownInitial = 30 * time.Second
	routeCooldownMax     = 10 * time.Minute
)

var relayablePaths = []*regexp.Regexp{
	regexp.MustCompile(`^/api/v1/heartbeat$`),
	regexp.MustCompile(`^/api/v1/commands/[^/]{1,64}/result$`),
	regexp.MustCompile(`^/api/v1/agents/me/inventory$`),
	regexp.MustCompile(`^/api/v1/agents/me/monitoring/results$`),
	regexp.MustCompile(`^/api/v1/agents/credentials/renew$`),
}

// Route is one relay the agent may use, best first.
type Route struct {
	ID          string
	BaseURL     string
	TLSSPKIPins []string
}

type routeState struct {
	id       string
	baseURL  string
	http     *http.Client
	failures int
	until    time.Time
}

// SetRoutes installs the relay routes from a verified manifest, valid until
// expiresAt. The origin is implicit and always tried last. A nil or empty list
// (or a zero expiresAt) restores origin-only polling. Each relay gets its own
// HTTP client so its TLS pins apply to that host alone.
func (c *Client) SetRoutes(routes []Route, expiresAt time.Time) error {
	built := make([]*routeState, 0, len(routes))
	for _, route := range routes {
		relayClient, err := NewWithTLSSPKIPins(route.BaseURL, "", route.TLSSPKIPins)
		if err != nil {
			return fmt.Errorf("relay route %s: %w", route.ID, err)
		}
		built = append(built, &routeState{
			id:      route.ID,
			baseURL: relayClient.baseURL,
			http:    relayClient.http,
		})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Keep cooldowns for relays that survive a manifest refresh, so a relay
	// that just failed is not retried first because the list was re-sent.
	previous := make(map[string]*routeState, len(c.routes))
	for _, state := range c.routes {
		previous[state.id] = state
	}
	for _, state := range built {
		if old, ok := previous[state.id]; ok {
			state.failures, state.until = old.failures, old.until
		}
	}
	c.routes = built
	c.routesExpireAt = expiresAt
	return nil
}

// LastRoute reports which route carried the most recent routed call:
// OriginRouteID or a relay ID.
func (c *Client) LastRoute() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.lastRoute == "" {
		return OriginRouteID
	}
	return c.lastRoute
}

func isRelayable(method, path string) bool {
	if method != http.MethodPost {
		return false
	}
	for _, pattern := range relayablePaths {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// activeRoutes returns the relays to try now, in order, skipping any in
// cooldown. It returns nothing once the manifest has expired.
func (c *Client) activeRoutes(now time.Time) []*routeState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.routes) == 0 || !now.Before(c.routesExpireAt) {
		return nil
	}
	out := make([]*routeState, 0, len(c.routes))
	for _, state := range c.routes {
		if now.Before(state.until) {
			continue
		}
		out = append(out, state)
	}
	return out
}

func (c *Client) markRoute(state *routeState, ok bool, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		state.failures = 0
		state.until = time.Time{}
		return
	}
	state.failures++
	cooldown := routeCooldownInitial << (state.failures - 1)
	if cooldown <= 0 || cooldown > routeCooldownMax {
		cooldown = routeCooldownMax
	}
	state.until = now.Add(cooldown)
}

func (c *Client) setLastRoute(id string) {
	c.mu.Lock()
	c.lastRoute = id
	c.mu.Unlock()
}

// shouldFailover decides whether an error means "this route is unusable, try
// the next one" rather than "the request itself was refused". Transport errors,
// 5xx, 429, and relay/residency refusal codes fail over. A 401 never does: it is
// a credential decision the caller must handle, and retrying it through another
// path would only multiply the refusal.
func shouldFailover(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se *StatusError
	if !errors.As(err, &se) {
		return true // transport-level failure: DNS, TLS, pin mismatch, reset
	}
	switch {
	case se.StatusCode >= 500, se.StatusCode == http.StatusTooManyRequests:
		return true
	case se.StatusCode == http.StatusUnauthorized:
		return false
	}
	return strings.Contains(se.Message, `"code":"relay_`) ||
		strings.Contains(se.Message, `"code": "relay_`) ||
		strings.Contains(se.Message, `"code":"residency_`) ||
		strings.Contains(se.Message, `"code": "residency_`)
}
