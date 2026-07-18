//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package service

import "errors"

// errUnsupported is returned by the service-control entry points on platforms
// without a Windows Service Control Manager. The agent still runs fine in the
// foreground on these platforms via the runtime in runner.go.
var errUnsupported = errors.New("service install/uninstall/start/stop is only supported on Windows")

// IsService always reports false off Windows; there is no SCM to launch us.
func IsService() (bool, error) { return false, nil }

// RunService is never reached off Windows (IsService is false) but must exist so
// the shared entry point compiles for all targets.
func RunService(version string) error { return errUnsupported }

// Install registers the agent as a service. Unsupported off Windows.
func Install(configSrc string) error { return errUnsupported }

// Uninstall removes the service. Unsupported off Windows.
func Uninstall() error { return errUnsupported }

// Start starts the installed service. Unsupported off Windows.
func Start() error { return errUnsupported }

// Stop stops the running service. Unsupported off Windows.
func Stop() error { return errUnsupported }
