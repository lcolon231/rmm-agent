//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"os"
	"os/exec"
	"syscall"
)

// pgidContainment puts the command in its own process group (Setpgid) so a
// timeout, cancellation, or service stop can signal the whole group — the shell
// and any children it spawned — instead of only the direct child. Without this,
// an orphaned descendant keeps the command's stdout pipe open and Wait blocks
// until it exits. Linux/macOS are development artifacts, but process-group
// containment is cheap and makes tree termination testable off Windows.
type pgidContainment struct{ pid int }

func newContainment() (containment, error) { return &pgidContainment{}, nil }

func (c *pgidContainment) prepare(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// The child becomes the leader of a new group whose pgid equals its pid.
	cmd.SysProcAttr.Setpgid = true
}

func (c *pgidContainment) assign(p *os.Process) error {
	c.pid = p.Pid
	return nil
}

func (c *pgidContainment) terminate() {
	if c.pid > 0 {
		// Negative pid signals the whole process group led by c.pid.
		_ = syscall.Kill(-c.pid, syscall.SIGKILL)
	}
}

func (c *pgidContainment) release() {}
