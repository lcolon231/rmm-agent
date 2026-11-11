// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	listTimeout    = 60 * time.Second
	controlTimeout = 90 * time.Second
)

// psRunner runs a bounded PowerShell command with an optional single
// environment value bound to NL_ARG, so a validated target name/id never
// enters the script text itself. It returns combined stdout+stderr.
//
// The Windows build binds it to powershell.exe. The glue below lives in an
// untagged file so every CI job covers it; tests feed captured output.
type psRunner func(ctx context.Context, timeout time.Duration, arg, script string) ([]byte, error)

const (
	listServicesScript  = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName | ConvertTo-Json -Compress"
	listProcessesScript = "Get-CimInstance Win32_Process | Select-Object ProcessId,Name | ConvertTo-Json -Compress"
	processNameScript   = "$p = Get-Process -Id ([int]$env:NL_ARG) -ErrorAction SilentlyContinue; if ($p) { $p.ProcessName } else { Write-Output 'NL_NOTFOUND' }"
	terminateScript     = "$ErrorActionPreference='Stop'; Stop-Process -Id ([int]$env:NL_ARG) -Force"
)

func psListServices(ctx context.Context, run psRunner) ([]ServiceInfo, error) {
	out, err := run(ctx, listTimeout, "", listServicesScript)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
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

func psListProcesses(ctx context.Context, run psRunner) ([]ProcessInfo, error) {
	out, err := run(ctx, listTimeout, "", listProcessesScript)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
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

func psControlService(ctx context.Context, run psRunner, name, action string) (string, error) {
	script, err := controlServiceScript(action)
	if err != nil {
		return "", err
	}
	out, err := run(ctx, controlTimeout, name, script)
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, "NL_NOTFOUND") {
		return "", fmt.Errorf("service does not exist")
	}
	if err != nil {
		return "", fmt.Errorf("%s", firstLine(text))
	}
	return lastLine(text), nil
}

func psProcessName(ctx context.Context, run psRunner, pid int) (string, error) {
	out, err := run(ctx, listTimeout, strconv.Itoa(pid), processNameScript)
	text := strings.TrimSpace(string(out))
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

func psTerminateProcess(ctx context.Context, run psRunner, pid int) error {
	out, err := run(ctx, controlTimeout, strconv.Itoa(pid), terminateScript)
	if err != nil {
		return fmt.Errorf("%s", firstLine(strings.TrimSpace(string(out))))
	}
	return nil
}
