//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	listTimeout    = 60 * time.Second
	controlTimeout = 90 * time.Second
)

// runPS runs a bounded PowerShell command with an optional single environment
// value bound to NL_ARG, so a validated target name/id never enters the script
// text itself.
func runPS(ctx context.Context, timeout time.Duration, arg, script string) ([]byte, error) {
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(bounded, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if arg != "" {
		cmd.Env = append(cmd.Environ(), "NL_ARG="+arg)
	}
	return cmd.CombinedOutput()
}

func platformListServices(ctx context.Context) ([]ServiceInfo, error) {
	out, err := runPS(ctx, listTimeout, "",
		"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName | ConvertTo-Json -Compress")
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

func platformListProcesses(ctx context.Context) ([]ProcessInfo, error) {
	out, err := runPS(ctx, listTimeout, "",
		"Get-CimInstance Win32_Process | Select-Object ProcessId,Name | ConvertTo-Json -Compress")
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

func platformControlService(ctx context.Context, name, action string) (string, error) {
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
	script := "$ErrorActionPreference='Stop'; " +
		"try { $null = Get-Service -Name $env:NL_ARG -ErrorAction Stop } catch { Write-Output 'NL_NOTFOUND'; exit 3 }; " +
		verb + "; (Get-Service -Name $env:NL_ARG).Status.ToString()"
	out, err := runPS(ctx, controlTimeout, name, script)
	text := strings.TrimSpace(string(out))
	if strings.Contains(text, "NL_NOTFOUND") {
		return "", fmt.Errorf("service does not exist")
	}
	if err != nil {
		return "", fmt.Errorf("%s", firstLine(text))
	}
	return lastLine(text), nil
}

func platformProcessName(ctx context.Context, pid int) (string, error) {
	out, err := runPS(ctx, listTimeout, fmt.Sprintf("%d", pid),
		"$p = Get-Process -Id ([int]$env:NL_ARG) -ErrorAction SilentlyContinue; if ($p) { $p.ProcessName } else { Write-Output 'NL_NOTFOUND' }")
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

func platformTerminateProcess(ctx context.Context, pid int) error {
	out, err := runPS(ctx, controlTimeout, fmt.Sprintf("%d", pid),
		"$ErrorActionPreference='Stop'; Stop-Process -Id ([int]$env:NL_ARG) -Force")
	if err != nil {
		return fmt.Errorf("%s", firstLine(strings.TrimSpace(string(out))))
	}
	return nil
}

// unmarshalMaybeArray decodes ConvertTo-Json output, which emits a bare object
// (not an array) when there is exactly one row and nothing for zero rows.
func unmarshalMaybeArray(data []byte, target any) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil
	}
	if strings.HasPrefix(trimmed, "[") {
		return json.Unmarshal([]byte(trimmed), target)
	}
	// Wrap a single object in an array so the caller always sees a slice.
	return json.Unmarshal([]byte("["+trimmed+"]"), target)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	if s == "" {
		return "service control failed"
	}
	return s
}

func lastLine(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == '\r' || r == '\n' })
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(fields[len(fields)-1])
}
