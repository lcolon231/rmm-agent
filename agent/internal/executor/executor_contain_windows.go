//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// jobContainment contains a command and its descendants in a Windows Job Object
// (issue #113). The job is configured with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
// so closing the job handle — on normal completion, timeout, cancellation, or
// service stop — terminates every process still in the job, not just the direct
// child. This is what proves a timed-out or cancelled command cannot leave
// orphaned grandchildren behind.
//
// The process is assigned to the job immediately after it starts. A descendant
// spawned in the brief window before assignment could escape the job; in
// practice the shell has not yet run the script by then, and kill-on-close plus
// exec.CommandContext's own kill of the direct child are the backstops.
type jobContainment struct {
	job windows.Handle
}

func newContainment() (containment, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	return &jobContainment{job: job}, nil
}

func (c *jobContainment) prepare(*exec.Cmd) {
	// Nothing to configure before start: the process is placed into the Job
	// Object in assign(), immediately after it starts.
}

func (c *jobContainment) assign(p *os.Process) error {
	h, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(p.Pid),
	)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(c.job, h)
}

func (c *jobContainment) terminate() {
	// Best-effort: the process may already have exited. Kill-on-close on
	// release() is the final backstop regardless.
	_ = windows.TerminateJobObject(c.job, 1)
}

func (c *jobContainment) release() {
	// Closing the job handle terminates any process still assigned to it
	// (kill-on-close), then frees the handle.
	_ = windows.CloseHandle(c.job)
}
