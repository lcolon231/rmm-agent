// SPDX-License-Identifier: AGPL-3.0-only
package chatpipe

import (
	"testing"
	"time"
)

func TestSessionRateLimitAndSessionZeroRefused(t *testing.T) {
	limiter := SessionLimiter{}
	now := time.Now()
	if limiter.Allow(0, now) || limiter.Allow(0xffffffff, now) {
		t.Fatal("noninteractive session admitted")
	}
	if !limiter.Allow(10, now) || limiter.Allow(10, now) || !limiter.Allow(11, now) {
		t.Fatal("limit must be per session")
	}
	if !limiter.Allow(10, now.Add(10*time.Second)) {
		t.Fatal("window did not expire")
	}
}
