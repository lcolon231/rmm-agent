package service

import (
	"math/rand"
	"testing"
	"time"
)

func TestBackoffWindowGrowsAndCaps(t *testing.T) {
	b := newBackoff(100*time.Millisecond, 2*time.Second, 2.0, rand.New(rand.NewSource(1)))

	want := []time.Duration{
		100 * time.Millisecond,
		200 * time.Millisecond,
		400 * time.Millisecond,
		800 * time.Millisecond,
		1600 * time.Millisecond,
		2 * time.Second, // capped
		2 * time.Second, // stays capped
	}
	for i, w := range want {
		if got := b.window(i); got != w {
			t.Fatalf("window(%d) = %s, want %s", i, got, w)
		}
	}
}

func TestBackoffNextStaysWithinJitterBounds(t *testing.T) {
	b := newBackoff(100*time.Millisecond, 2*time.Second, 2.0, rand.New(rand.NewSource(42)))

	// Equal jitter keeps each delay in [window/2, window].
	for attempt := 0; attempt < 10; attempt++ {
		window := b.window(attempt)
		got := b.Next()
		if got < window/2 || got > window {
			t.Fatalf("attempt %d: Next() = %s, want within [%s, %s]", attempt, got, window/2, window)
		}
	}
}

func TestBackoffNeverExceedsCap(t *testing.T) {
	b := newBackoff(1*time.Second, 5*time.Second, 2.0, rand.New(rand.NewSource(7)))
	for i := 0; i < 50; i++ {
		if got := b.Next(); got > 5*time.Second {
			t.Fatalf("Next() = %s exceeded cap 5s", got)
		}
	}
}

func TestBackoffReset(t *testing.T) {
	b := newBackoff(100*time.Millisecond, 2*time.Second, 2.0, rand.New(rand.NewSource(1)))
	b.Next()
	b.Next()
	b.Next()
	if b.attempt == 0 {
		t.Fatal("attempt should have advanced before reset")
	}
	b.Reset()
	if b.attempt != 0 {
		t.Fatalf("after Reset, attempt = %d, want 0", b.attempt)
	}
	// After reset the window should be back to Initial.
	if got := b.window(0); got != 100*time.Millisecond {
		t.Fatalf("window(0) after reset = %s, want 100ms", got)
	}
}

func TestBackoffDefaults(t *testing.T) {
	// Zero/invalid inputs should be coerced to sane values, not panic.
	b := newBackoff(0, 0, 0, rand.New(rand.NewSource(1)))
	if b.Initial <= 0 || b.Max < b.Initial || b.Factor < 1 {
		t.Fatalf("defaults not applied: %+v", b)
	}
	_ = b.Next()
}
