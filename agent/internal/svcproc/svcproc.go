// SPDX-License-Identifier: AGPL-3.0-only
// Package svcproc implements the typed Windows service and process management
// contract introduced by issue #57. Listing services and processes is read-only;
// service control (start/stop/restart) and process termination are validated,
// confirmed, and guarded by a protected-target denylist so a technician cannot
// disable the security stack, the agent itself, or a critical OS process. The
// server has already validated and signed the payload; the agent re-validates
// structurally and re-checks protected targets at the endpoint. It never accepts
// script text.
package svcproc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

const (
	ActionStart   = "start"
	ActionStop    = "stop"
	ActionRestart = "restart"

	// MaxServices and MaxProcesses bound a listing so one command cannot return an
	// unbounded result.
	MaxServices  = 1000
	MaxProcesses = 2000
)

var (
	serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.\- ]{1,256}$`)
	controlChar        = func(r rune) bool { return r < 32 || r == 127 }
)

// ProtectedServices is the case-insensitive denylist of services that may never
// be controlled: the agent's own service, the security stack, and core OS
// services whose loss would break the endpoint or NodeLink's own connectivity.
// It MUST stay in sync with the server's PROTECTED_SERVICES.
var ProtectedServices = map[string]bool{
	"nodelinkagent": true, "windefend": true, "mpssvc": true, "eventlog": true,
	"rpcss": true, "dcomlaunch": true, "rpceptmapper": true, "winmgmt": true,
	"lsm": true, "dnscache": true, "dhcp": true, "bfe": true, "gpsvc": true,
	"netlogon": true, "samss": true, "cryptsvc": true, "schedule": true,
	"profsvc": true, "plugplay": true, "power": true, "nsi": true,
}

// ProtectedProcesses is the case-insensitive image-name denylist for termination:
// core Windows processes (killing any is fatal to the session/OS) plus the
// service host and the agent's own image. PIDs 0 and 4 are additionally refused.
// It MUST stay in sync with the server's PROTECTED_PROCESSES.
var ProtectedProcesses = map[string]bool{
	"system": true, "idle": true, "smss.exe": true, "csrss.exe": true,
	"wininit.exe": true, "winlogon.exe": true, "services.exe": true,
	"lsass.exe": true, "lsm.exe": true, "svchost.exe": true,
	"nodelinkagent.exe": true,
}

// ServiceInfo is one row of a service listing.
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state,omitempty"`
	StartMode   string `json:"start_mode,omitempty"`
	Account     string `json:"account,omitempty"`
}

// ProcessInfo is one row of a process listing.
type ProcessInfo struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type controlPayload struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Confirm bool   `json:"confirm"`
	Reason  string `json:"reason"`
}

type terminatePayload struct {
	PID          int    `json:"pid"`
	ExpectedName string `json:"expected_name,omitempty"`
	Confirm      bool   `json:"confirm"`
	Reason       string `json:"reason"`
}

// ListServicesResult / ListProcessesResult are the read-only listing evidence.
type ListServicesResult struct {
	Status    string        `json:"status"`
	Services  []ServiceInfo `json:"services"`
	Count     int           `json:"count"`
	Truncated bool          `json:"truncated,omitempty"`
	Message   string        `json:"message,omitempty"`
}

type ListProcessesResult struct {
	Status    string        `json:"status"`
	Processes []ProcessInfo `json:"processes"`
	Count     int           `json:"count"`
	Truncated bool          `json:"truncated,omitempty"`
	Message   string        `json:"message,omitempty"`
}

// ControlServiceResult / TerminateProcessResult are the mutation evidence.
type ControlServiceResult struct {
	Status       string `json:"status"`
	Service      string `json:"service"`
	Action       string `json:"action"`
	State        string `json:"state,omitempty"`
	ReasonSHA256 string `json:"reason_sha256"`
	Message      string `json:"message,omitempty"`
}

type TerminateProcessResult struct {
	Status       string `json:"status"`
	PID          int    `json:"pid"`
	Name         string `json:"name,omitempty"`
	ReasonSHA256 string `json:"reason_sha256"`
	Message      string `json:"message,omitempty"`
}

// Function seams keep platform calls mockable so tests never touch real services
// or processes.
var (
	listServicesFn     = platformListServices
	controlServiceFn   = platformControlService
	listProcessesFn    = platformListProcesses
	terminateProcessFn = platformTerminateProcess
	resolveProcessName = platformProcessName
	selfPID            = os.Getpid
)

func decodeStrict(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func reasonDigest(reason string) string {
	sum := sha256.Sum256([]byte(reason))
	return hex.EncodeToString(sum[:])
}

func validateReason(reason string) bool {
	return reason == strings.TrimSpace(reason) && len(reason) >= 10 && len(reason) <= 512 &&
		strings.IndexFunc(reason, controlChar) < 0
}

// Execute dispatches one service/process command and returns JSON evidence.
func Execute(ctx context.Context, kind string, raw json.RawMessage) executor.Result {
	switch kind {
	case executor.KindListServices:
		return executeListServices(ctx, raw)
	case executor.KindListProcesses:
		return executeListProcesses(ctx, raw)
	case executor.KindControlService:
		return executeControlService(ctx, raw)
	case executor.KindTerminateProcess:
		return executeTerminateProcess(ctx, raw)
	default:
		out, _ := json.Marshal(map[string]string{"status": "unsupported"})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: "unsupported service/process operation"}
	}
}

func executeListServices(ctx context.Context, raw json.RawMessage) executor.Result {
	if err := decodeStrict(raw, &struct{}{}); err != nil && len(raw) > 0 && string(raw) != "{}" {
		out, _ := json.Marshal(ListServicesResult{Status: "invalid", Services: []ServiceInfo{}, Message: "list_services takes no fields"})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: "list_services payload is invalid"}
	}
	services, err := listServicesFn(ctx)
	if err != nil {
		out, _ := json.Marshal(ListServicesResult{Status: "unavailable", Services: []ServiceInfo{}, Message: err.Error()})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: "list services failed: " + err.Error()}
	}
	truncated := false
	if len(services) > MaxServices {
		services = services[:MaxServices]
		truncated = true
	}
	if services == nil {
		services = []ServiceInfo{}
	}
	out, _ := json.Marshal(ListServicesResult{Status: "ok", Services: services, Count: len(services), Truncated: truncated})
	return executor.Result{ExitCode: 0, Stdout: string(out)}
}

func executeListProcesses(ctx context.Context, raw json.RawMessage) executor.Result {
	if err := decodeStrict(raw, &struct{}{}); err != nil && len(raw) > 0 && string(raw) != "{}" {
		out, _ := json.Marshal(ListProcessesResult{Status: "invalid", Processes: []ProcessInfo{}, Message: "list_processes takes no fields"})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: "list_processes payload is invalid"}
	}
	processes, err := listProcessesFn(ctx)
	if err != nil {
		out, _ := json.Marshal(ListProcessesResult{Status: "unavailable", Processes: []ProcessInfo{}, Message: err.Error()})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: "list processes failed: " + err.Error()}
	}
	truncated := false
	if len(processes) > MaxProcesses {
		processes = processes[:MaxProcesses]
		truncated = true
	}
	if processes == nil {
		processes = []ProcessInfo{}
	}
	out, _ := json.Marshal(ListProcessesResult{Status: "ok", Processes: processes, Count: len(processes), Truncated: truncated})
	return executor.Result{ExitCode: 0, Stdout: string(out)}
}

func controlResult(status, service, action, state, reason, stderr string) executor.Result {
	out, _ := json.Marshal(ControlServiceResult{
		Status: status, Service: service, Action: action, State: state,
		ReasonSHA256: reasonDigest(reason), Message: stderr,
	})
	exit := 0
	if status != "ok" {
		exit = 1
	}
	return executor.Result{ExitCode: exit, Stdout: string(out), Stderr: stderr}
}

func executeControlService(ctx context.Context, raw json.RawMessage) executor.Result {
	var p controlPayload
	if err := decodeStrict(raw, &p); err != nil {
		return controlResult("invalid", "", "", "", "", "control_service payload is invalid")
	}
	if !serviceNamePattern.MatchString(p.Name) || !p.Confirm || !validateReason(p.Reason) ||
		(p.Action != ActionStart && p.Action != ActionStop && p.Action != ActionRestart) {
		return controlResult("invalid", p.Name, p.Action, "", p.Reason, "control_service payload is invalid")
	}
	if ProtectedServices[strings.ToLower(strings.TrimSpace(p.Name))] {
		return controlResult("protected", p.Name, p.Action, "", p.Reason, "service is protected and cannot be controlled")
	}
	state, err := controlServiceFn(ctx, p.Name, p.Action)
	if err != nil {
		status := "failed"
		if strings.Contains(strings.ToLower(err.Error()), "not") && strings.Contains(strings.ToLower(err.Error()), "exist") {
			status = "not_found"
		}
		return controlResult(status, p.Name, p.Action, state, p.Reason, err.Error())
	}
	return controlResult("ok", p.Name, p.Action, state, p.Reason, "")
}

func terminateResult(status string, pid int, name, reason, stderr string) executor.Result {
	out, _ := json.Marshal(TerminateProcessResult{
		Status: status, PID: pid, Name: name, ReasonSHA256: reasonDigest(reason), Message: stderr,
	})
	exit := 0
	if status != "ok" {
		exit = 1
	}
	return executor.Result{ExitCode: exit, Stdout: string(out), Stderr: stderr}
}

func executeTerminateProcess(ctx context.Context, raw json.RawMessage) executor.Result {
	var p terminatePayload
	if err := decodeStrict(raw, &p); err != nil {
		return terminateResult("invalid", 0, "", "", "terminate_process payload is invalid")
	}
	if p.PID < 0 || !p.Confirm || !validateReason(p.Reason) ||
		(p.ExpectedName != "" && (len(p.ExpectedName) > 260 || strings.IndexFunc(p.ExpectedName, controlChar) >= 0)) {
		return terminateResult("invalid", p.PID, p.ExpectedName, p.Reason, "terminate_process payload is invalid")
	}
	// PIDs 0 (System Idle) and 4 (System) are always protected, as is this agent.
	if p.PID == 0 || p.PID == 4 || p.PID == selfPID() {
		return terminateResult("protected", p.PID, p.ExpectedName, p.Reason, "process is protected and cannot be terminated")
	}
	// Resolve the live image name and re-check the protected denylist — the agent
	// is authoritative here because the server only sees the operator-supplied pid.
	name, err := resolveProcessName(ctx, p.PID)
	if err != nil {
		return terminateResult("not_found", p.PID, p.ExpectedName, p.Reason, "process not found")
	}
	if ProtectedProcesses[strings.ToLower(strings.TrimSpace(name))] {
		return terminateResult("protected", p.PID, name, p.Reason, "process is protected and cannot be terminated")
	}
	// If the operator pinned an expected image name, refuse a pid that has since
	// been recycled to a different process.
	if p.ExpectedName != "" && !strings.EqualFold(strings.TrimSpace(p.ExpectedName), strings.TrimSpace(name)) {
		return terminateResult("name_mismatch", p.PID, name, p.Reason, "process image name did not match expected_name")
	}
	if err := terminateProcessFn(ctx, p.PID); err != nil {
		return terminateResult("failed", p.PID, name, p.Reason, err.Error())
	}
	return terminateResult("ok", p.PID, name, p.Reason, "")
}
