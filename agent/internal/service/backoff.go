// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"math/rand"
	"time"
)

// Backoff computes exponentially increasing wait durations with jitter, capped
// at a maximum. It spaces out retries when the server is unreachable so a down
// server produces quiet, bounded retries rather than a tight error loop.
//
// Backoff is not safe for concurrent use; it is driven from a single check-in
// loop.
type Backoff struct {
	// Initial is the base window for the first retry.
	Initial time.Duration
	// Max caps the window (jitter is applied within the capped window).
	Max time.Duration
	// Factor is the multiplier applied per attempt (typically 2).
	Factor float64

	rnd     *rand.Rand
	attempt int
}

// newBackoff builds a Backoff, coercing zero/invalid fields to sane defaults.
func newBackoff(initial, max time.Duration, factor float64, rnd *rand.Rand) *Backoff {
	if initial <= 0 {
		initial = time.Second
	}
	if max < initial {
		max = initial
	}
	if factor < 1 {
		factor = 2
	}
	if rnd == nil {
		rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return &Backoff{Initial: initial, Max: max, Factor: factor, rnd: rnd}
}

// window returns the capped exponential window for a given attempt, before
// jitter is applied.
func (b *Backoff) window(attempt int) time.Duration {
	d := float64(b.Initial)
	for i := 0; i < attempt; i++ {
		d *= b.Factor
		if d >= float64(b.Max) {
			return b.Max
		}
	}
	return time.Duration(d)
}

// Next returns the next delay and advances the attempt counter. It uses "equal
// jitter": half the capped window plus a random point in the other half, so
// delays fall in [window/2, window] and never synchronize across many agents.
func (b *Backoff) Next() time.Duration {
	window := b.window(b.attempt)
	b.attempt++
	half := window / 2
	if half <= 0 {
		return window
	}
	return half + time.Duration(b.rnd.Int63n(int64(half)+1))
}

// Reset returns the backoff to its initial state, called after a success.
func (b *Backoff) Reset() { b.attempt = 0 }
