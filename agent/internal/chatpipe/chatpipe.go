// SPDX-License-Identifier: AGPL-3.0-only
// Package chatpipe accepts a parameterless, local interactive open-chat request.
package chatpipe

import (
	"context"
	"errors"
	"time"
)

const Name = `\\.\pipe\nodelink-agent-chat`
const openRequest byte = 1

var ErrUnavailable = errors.New("NodeLink Support is unavailable; check that the NodeLinkAgent service is running")
var ErrRefused = errors.New("NodeLink Support could not open; try again shortly or contact your technician")
var ErrUnsupported = errors.New("support chat requires Windows")

type Handler func(context.Context, uint32) error

// SessionLimiter is used by the single pipe loop, not concurrent goroutines.
type SessionLimiter map[uint32]time.Time

func (l SessionLimiter) Allow(id uint32, now time.Time) bool {
	for session, until := range l {
		if !now.Before(until) {
			delete(l, session)
		}
	}
	if id == 0 || id == 0xffffffff {
		return false
	}
	if _, found := l[id]; found {
		return false
	}
	l[id] = now.Add(10 * time.Second)
	return true
}

func pause(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(50 * time.Millisecond):
		return true
	}
}
