// SPDX-License-Identifier: AGPL-3.0-only
// Package chattray shows the NodeLink Support system-tray icon. It is only a
// launcher: activating the icon makes the same parameterless local-pipe request
// as `rmm-agent chat`, so the service opens the conversation and the browser and
// the chat URL/token never crosses the pipe or a log.
package chattray

import "errors"

// ErrUnsupported is returned by non-Windows builds; the tray is Windows-only,
// matching the rest of the support-chat feature.
var ErrUnsupported = errors.New("support chat tray requires Windows")

// Run displays the tray icon and blocks until the user chooses Exit or the
// session ends. A second instance in the same session exits quietly.
func Run() error { return run() }
