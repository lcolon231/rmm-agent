// SPDX-License-Identifier: AGPL-3.0-only
// Package chatlaunch launches a browser with a captured interactive user token.
package chatlaunch

import (
	"errors"
	"net/url"
	"strings"
)

var ErrUnsupported = errors.New("support chat requires Windows")
var ErrNoSession = errors.New("no interactive user session")
var ErrLaunch = errors.New("support chat browser launch failed")
var ErrURL = errors.New("invalid support chat URL")

// Target captures the caller's session before the network request. A concurrent
// console switch cannot redirect the credential-bearing browser launch.
type Target struct {
	launch  func(string) error
	release func()
}

func (t *Target) Close() { t.release() }
func (t *Target) Open(raw string) error {
	if !validURL(raw) {
		return ErrURL
	}
	return t.launch(raw)
}

func validURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 4096 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.Path == "/chat" && u.RawQuery == "" && u.Fragment != "" && !strings.ContainsAny(raw, "\x00\r\n\" ")
}

// Open is for single-console callers. The pipe path always uses ForSession.
func Open(raw string) error { return openConsole(raw) }
