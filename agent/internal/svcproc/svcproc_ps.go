// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

const (
	listTimeout    = 60 * time.Second
	controlTimeout = 90 * time.Second
)

// The glue below runs through a pwsh.Runner, binding an optional single target
// value to NL_ARG so a validated name/id never enters the script text itself.
// The Windows build binds it to pwsh.Exec. It lives in an untagged file so
// every CI job covers it; tests feed captured output.

// script builds the Script for body, with target bound to NL_ARG when set.
func script(body, target string, timeout time.Duration) pwsh.Script {
	s := pwsh.Script{Body: body, Timeout: timeout}
	if target != "" {
		s.Env = map[string]string{"NL_ARG": target}
	}
	return s
}

// failureDetail is the text to report for a failed run: PowerShell writes
// errors to stderr, but a script's own message may be on stdout. A run that
// printed nothing, such as one killed at its timeout, reports err instead.
func failureDetail(res pwsh.Result, err error) string {
	if text := strings.TrimSpace(string(res.Stderr)); text != "" {
		return text
	}
	if text := strings.TrimSpace(string(res.Stdout)); text != "" {
		return text
	}
	if err != nil && !errors.As(err, new(*pwsh.ExitError)) {
		return err.Error()
	}
	return ""
}

const (
	listServicesScript  = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName | ConvertTo-Json -Compress"
	listProcessesScript = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name | ConvertTo-Json -Compress"
	processNameScript   = "$p = Get-Process -Id ([int]$env:NL_ARG) -ErrorAction SilentlyContinue; if ($p) { $p.ProcessName } else { Write-Output 'NL_NOTFOUND' }"
	terminateScript     = "$ErrorActionPreference='Stop'; Stop-Process -Id ([int]$env:NL_ARG) -Force"
)

func psListServices(ctx context.Context, run pwsh.Runner) ([]ServiceInfo, error) {
	res, err := run(ctx, script(listServicesScript, "", listTimeout))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, failureDetail(res, nil))
	}
	out := res.Stdout
	var rows []struct {
		Name        string `json:"Name"`
		DisplayName string `json:"DisplayName"`
		State       string `json:"State"`
		StartMode   string `json:"StartMode"`
		StartName   string `json:"StartName"`
	}
	if err := unmarshalMaybeArray(out, &rows); err != nil {
		return nil, err
	}
	services := make([]ServiceInfo, 0, len(rows))
	for _, r := range rows {
		services = append(services, ServiceInfo{
			Name: r.Name, DisplayName: r.DisplayName, State: r.State,
			StartMode: r.StartMode, Account: r.StartName,
		})
	}
	return services, nil
}

func psListProcesses(ctx context.Context, run pwsh.Runner) ([]ProcessInfo, error) {
	res, err := run(ctx, script(listProcessesScript, "", listTimeout))
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, failureDetail(res, nil))
	}
	out := res.Stdout
	var rows []struct {
		ProcessID int    `json:"ProcessId"`
		Name      string `json:"Name"`
	}
	if err := unmarshalMaybeArray(out, &rows); err != nil {
		return nil, err
	}
	processes := make([]ProcessInfo, 0, len(rows))
	for _, r := range rows {
		processes = append(processes, ProcessInfo{PID: r.ProcessID, Name: r.Name})
	}
	return processes, nil
}

func controlServiceScript(action string) (string, error) {
	var verb string
	switch action {
	case ActionStart:
		verb = "Start-Service -Name $env:NL_ARG"
	case ActionStop:
		// No -Force: refuse rather than cascade-stop dependent services.
		verb = "Stop-Service -Name $env:NL_ARG"
	case ActionRestart:
		verb = "Restart-Service -Name $env:NL_ARG"
	default:
		return "", fmt.Errorf("unsupported action %q", action)
	}
	return "$ErrorActionPreference='Stop'; " +
		"try { $null = Get-Service -Name $env:NL_ARG -ErrorAction Stop } catch { Write-Output 'NL_NOTFOUND'; exit 3 }; " +
		verb + "; (Get-Service -Name $env:NL_ARG).Status.ToString()", nil
}

func psControlService(ctx context.Context, run pwsh.Runner, name, action string) (string, error) {
	body, err := controlServiceScript(action)
	if err != nil {
		return "", err
	}
	res, err := run(ctx, script(body, name, controlTimeout))
	text := strings.TrimSpace(string(res.Stdout))
	if strings.Contains(text, "NL_NOTFOUND") {
		return "", fmt.Errorf("service does not exist")
	}
	if err != nil {
		return "", fmt.Errorf("%s", firstLine(failureDetail(res, err)))
	}
	return lastLine(text), nil
}

func psProcessName(ctx context.Context, run pwsh.Runner, pid int) (string, error) {
	res, err := run(ctx, script(processNameScript, strconv.Itoa(pid), listTimeout))
	text := strings.TrimSpace(string(res.Stdout))
	if err != nil || text == "" || strings.Contains(text, "NL_NOTFOUND") {
		return "", fmt.Errorf("process not found")
	}
	name := lastLine(text)
	// Get-Process reports the image base name without the extension; normalize to
	// the .exe form the protected denylist uses.
	if !strings.Contains(name, ".") {
		name += ".exe"
	}
	return name, nil
}

func psTerminateProcess(ctx context.Context, run pwsh.Runner, pid int) error {
	res, err := run(ctx, script(terminateScript, strconv.Itoa(pid), controlTimeout))
	if err != nil {
		return fmt.Errorf("%s", firstLine(failureDetail(res, err)))
	}
	return nil
}
