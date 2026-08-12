//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package executor

import (
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func buildCommand(kind, script string) *exec.Cmd {
	switch kind {
	case KindPowerShell, KindInventory:
		return exec.Command("powershell.exe",
			"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
			"-Command", script)
	case KindShell:
		return exec.Command("cmd.exe", "/C", script)
	default:
		return nil
	}
}

func interactiveCommand() *exec.Cmd {
	return exec.Command("powershell.exe",
		"-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-Command", "-")
}

var ntResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

// runCommand starts the command suspended, assigns it to a kill-on-close Job
// Object, then resumes it. Suspension closes the otherwise exploitable race in
// which a shell could spawn a descendant before Job assignment. Closing or
// terminating the Job kills the complete process tree on timeout, service
// stop, agent crash, and normal parent exit.
func runCommand(ctx context.Context, cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("create command job object: %w", err)
	}
	defer windows.CloseHandle(job)

	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		return fmt.Errorf("configure command job object: %w", err)
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.CREATE_SUSPENDED | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	process, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|
			windows.PROCESS_TERMINATE|
			windows.PROCESS_QUERY_LIMITED_INFORMATION|
			windows.PROCESS_SUSPEND_RESUME,
		false,
		uint32(cmd.Process.Pid),
	)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("open suspended command process: %w", err)
	}
	defer windows.CloseHandle(process)

	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return fmt.Errorf("assign command process to job object: %w", err)
	}
	status, _, _ := ntResumeProcess.Call(uintptr(process))
	if status != 0 {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Wait()
		return fmt.Errorf("resume command process: NTSTATUS 0x%x", status)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		// The deferred CloseHandle applies KILL_ON_JOB_CLOSE to descendants
		// that outlived their shell parent.
		return err
	case <-ctx.Done():
		_ = windows.TerminateJobObject(job, 1)
		<-done
		return ctx.Err()
	}
}
