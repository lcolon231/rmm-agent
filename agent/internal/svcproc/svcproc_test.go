// SPDX-License-Identifier: AGPL-3.0-only
package svcproc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

func withSeams(t *testing.T,
	lSvc func(context.Context) ([]ServiceInfo, error),
	cSvc func(context.Context, string, string) (string, error),
	lProc func(context.Context) ([]ProcessInfo, error),
	tProc func(context.Context, int) error,
	rName func(context.Context, int) (string, error),
	sPID func() int,
) {
	t.Helper()
	origLS, origCS, origLP, origTP, origRN, origSP := listServicesFn, controlServiceFn, listProcessesFn, terminateProcessFn, resolveProcessName, selfPID
	if lSvc != nil {
		listServicesFn = lSvc
	}
	if cSvc != nil {
		controlServiceFn = cSvc
	}
	if lProc != nil {
		listProcessesFn = lProc
	}
	if tProc != nil {
		terminateProcessFn = tProc
	}
	if rName != nil {
		resolveProcessName = rName
	}
	if sPID != nil {
		selfPID = sPID
	}
	t.Cleanup(func() {
		listServicesFn, controlServiceFn, listProcessesFn, terminateProcessFn, resolveProcessName, selfPID = origLS, origCS, origLP, origTP, origRN, origSP
	})
}

func TestExecuteListServicesSuccess(t *testing.T) {
	withSeams(t, func(_ context.Context) ([]ServiceInfo, error) {
		return []ServiceInfo{
			{Name: "Spooler", DisplayName: "Print Spooler", State: "Running", StartMode: "Auto", Account: "LocalSystem"},
			{Name: "W32Time", DisplayName: "Windows Time", State: "Stopped", StartMode: "Manual", Account: "NT AUTHORITY\\LocalService"},
		}, nil
	}, nil, nil, nil, nil, nil)

	res := Execute(context.Background(), executor.KindListServices, json.RawMessage("{}"))
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", res.ExitCode, res.Stderr)
	}

	var out ListServicesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "ok" || out.Count != 2 || len(out.Services) != 2 || out.Truncated {
		t.Fatalf("unexpected list_services output: %+v", out)
	}
}

func TestExecuteListServicesUnavailable(t *testing.T) {
	withSeams(t, func(_ context.Context) ([]ServiceInfo, error) {
		return nil, errors.New("CIM query failed")
	}, nil, nil, nil, nil, nil)

	res := Execute(context.Background(), executor.KindListServices, nil)
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for unavailable service list")
	}

	var out ListServicesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "unavailable" || out.Message == "" {
		t.Fatalf("unexpected list_services output: %+v", out)
	}
}

func TestExecuteListServicesTruncated(t *testing.T) {
	withSeams(t, func(_ context.Context) ([]ServiceInfo, error) {
		svcs := make([]ServiceInfo, MaxServices+50)
		for i := range svcs {
			svcs[i] = ServiceInfo{Name: fmt.Sprintf("Svc%d", i)}
		}
		return svcs, nil
	}, nil, nil, nil, nil, nil)

	res := Execute(context.Background(), executor.KindListServices, json.RawMessage("{}"))
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}

	var out ListServicesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "ok" || !out.Truncated || out.Count != MaxServices || len(out.Services) != MaxServices {
		t.Fatalf("expected truncation at MaxServices, got: %+v", out)
	}
}

func TestExecuteListServicesInvalidPayload(t *testing.T) {
	res := Execute(context.Background(), executor.KindListServices, json.RawMessage(`{"unexpected":"field"}`))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for invalid payload")
	}

	var out ListServicesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "invalid" {
		t.Fatalf("want status invalid, got %s", out.Status)
	}
}

func TestExecuteListProcessesSuccess(t *testing.T) {
	withSeams(t, nil, nil, func(_ context.Context) ([]ProcessInfo, error) {
		return []ProcessInfo{
			{PID: 100, Name: "explorer.exe"},
			{PID: 200, Name: "cmd.exe"},
		}, nil
	}, nil, nil, nil)

	res := Execute(context.Background(), executor.KindListProcesses, json.RawMessage("{}"))
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", res.ExitCode, res.Stderr)
	}

	var out ListProcessesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "ok" || out.Count != 2 || len(out.Processes) != 2 || out.Truncated {
		t.Fatalf("unexpected list_processes output: %+v", out)
	}
}

func TestExecuteListProcessesUnavailable(t *testing.T) {
	withSeams(t, nil, nil, func(_ context.Context) ([]ProcessInfo, error) {
		return nil, errors.New("process listing failed")
	}, nil, nil, nil)

	res := Execute(context.Background(), executor.KindListProcesses, nil)
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for unavailable process list")
	}

	var out ListProcessesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "unavailable" || out.Message == "" {
		t.Fatalf("unexpected list_processes output: %+v", out)
	}
}

func TestExecuteListProcessesTruncated(t *testing.T) {
	withSeams(t, nil, nil, func(_ context.Context) ([]ProcessInfo, error) {
		procs := make([]ProcessInfo, MaxProcesses+100)
		for i := range procs {
			procs[i] = ProcessInfo{PID: i + 1, Name: fmt.Sprintf("proc%d.exe", i)}
		}
		return procs, nil
	}, nil, nil, nil)

	res := Execute(context.Background(), executor.KindListProcesses, json.RawMessage("{}"))
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", res.ExitCode)
	}

	var out ListProcessesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "ok" || !out.Truncated || out.Count != MaxProcesses || len(out.Processes) != MaxProcesses {
		t.Fatalf("expected truncation at MaxProcesses, got: %+v", out)
	}
}

func TestExecuteListProcessesInvalidPayload(t *testing.T) {
	res := Execute(context.Background(), executor.KindListProcesses, json.RawMessage(`{"bad":"field"}`))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for invalid payload")
	}

	var out ListProcessesResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "invalid" {
		t.Fatalf("want status invalid, got %s", out.Status)
	}
}

func TestExecuteControlServiceSuccess(t *testing.T) {
	actions := []string{ActionStart, ActionStop, ActionRestart}
	for _, act := range actions {
		var gotName, gotAction string
		withSeams(t, nil, func(_ context.Context, name, action string) (string, error) {
			gotName, gotAction = name, action
			return "Running", nil
		}, nil, nil, nil, nil)

		payload := fmt.Sprintf(`{"name":"Spooler","action":"%s","confirm":true,"reason":"Valid reason for maintenance"}`, act)
		res := Execute(context.Background(), executor.KindControlService, json.RawMessage(payload))
		if res.ExitCode != 0 {
			t.Fatalf("action %s exit code = %d, want 0 (stderr=%s)", act, res.ExitCode, res.Stderr)
		}
		if gotName != "Spooler" || gotAction != act {
			t.Fatalf("seam received %s, %s", gotName, gotAction)
		}

		var out ControlServiceResult
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if out.Status != "ok" || out.Service != "Spooler" || out.Action != act || out.State != "Running" {
			t.Fatalf("unexpected control_service output: %+v", out)
		}
		if len(out.ReasonSHA256) != 64 {
			t.Fatalf("invalid reason sha256: %s", out.ReasonSHA256)
		}
	}
}

func TestExecuteControlServiceProtectedRefusal(t *testing.T) {
	protected := []string{"nodelinkagent", "NodeLinkAgent", "WinDefend", "wInMgMt", "  eventlog  ", "mpssvc", "rpcss"}
	for _, svc := range protected {
		called := false
		withSeams(t, nil, func(_ context.Context, _, _ string) (string, error) {
			called = true
			return "", nil
		}, nil, nil, nil, nil)

		payload := fmt.Sprintf(`{"name":%q,"action":"restart","confirm":true,"reason":"Valid reason for restart"}`, svc)
		res := Execute(context.Background(), executor.KindControlService, json.RawMessage(payload))
		if res.ExitCode == 0 {
			t.Fatalf("protected service %q must be refused with exit code 1", svc)
		}
		if called {
			t.Fatalf("protected service %q must not invoke platform seam", svc)
		}

		var out ControlServiceResult
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if out.Status != "protected" {
			t.Fatalf("want status protected for %q, got %s", svc, out.Status)
		}
	}
}

func TestExecuteControlServiceNotFound(t *testing.T) {
	withSeams(t, nil, func(_ context.Context, _, _ string) (string, error) {
		return "", errors.New("service does not exist")
	}, nil, nil, nil, nil)

	payload := `{"name":"NoSuchSvc","action":"start","confirm":true,"reason":"Valid reason for start"}`
	res := Execute(context.Background(), executor.KindControlService, json.RawMessage(payload))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for missing service")
	}

	var out ControlServiceResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "not_found" {
		t.Fatalf("want status not_found, got %s", out.Status)
	}
}

func TestExecuteControlServiceFailed(t *testing.T) {
	withSeams(t, nil, func(_ context.Context, _, _ string) (string, error) {
		return "", errors.New("access denied")
	}, nil, nil, nil, nil)

	payload := `{"name":"Spooler","action":"stop","confirm":true,"reason":"Valid reason for stop"}`
	res := Execute(context.Background(), executor.KindControlService, json.RawMessage(payload))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for failed service control")
	}

	var out ControlServiceResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "failed" || out.Message != "access denied" {
		t.Fatalf("unexpected control_service result: %+v", out)
	}
}

func TestExecuteControlServiceInvalidPayloads(t *testing.T) {
	cases := []string{
		`{"name":"Spooler","action":"pause","confirm":true,"reason":"Valid reason for pause"}`,
		`{"name":"Spooler","action":"start","confirm":false,"reason":"Valid reason for start"}`,
		`{"name":"Spooler","action":"start","confirm":true,"reason":"short"}`,
		`{"name":"Spooler","action":"start","confirm":true,"reason":"invalid reason\x07with control char"}`,
		`{"name":"Spooler;bad","action":"start","confirm":true,"reason":"Valid reason for start"}`,
		`{"name":"Spooler","action":"start","confirm":true,"reason":"` + strings.Repeat("a", 513) + `"}`,
		`{"name":"Spooler","action":"start","confirm":true,"reason":"  untrimmed reason  "}`,
		`{"name":"Spooler","action":"start","confirm":true,"reason":"Valid reason","extra":1}`,
	}

	for _, payload := range cases {
		res := Execute(context.Background(), executor.KindControlService, json.RawMessage(payload))
		if res.ExitCode == 0 {
			t.Fatalf("payload should have been rejected: %s", payload)
		}
		var out ControlServiceResult
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if out.Status != "invalid" {
			t.Fatalf("want status invalid for payload %s, got %s", payload, out.Status)
		}
	}
}

func TestExecuteTerminateProcessSuccess(t *testing.T) {
	var terminatedPID int
	withSeams(t, nil, nil, nil,
		func(_ context.Context, pid int) error {
			terminatedPID = pid
			return nil
		},
		func(_ context.Context, pid int) (string, error) {
			if pid == 1234 {
				return "notepad.exe", nil
			}
			return "", errors.New("not found")
		},
		func() int { return 9999 },
	)

	payload := `{"pid":1234,"expected_name":"notepad.exe","confirm":true,"reason":"Valid reason for terminate"}`
	res := Execute(context.Background(), executor.KindTerminateProcess, json.RawMessage(payload))
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr=%s)", res.ExitCode, res.Stderr)
	}
	if terminatedPID != 1234 {
		t.Fatalf("terminated PID = %d, want 1234", terminatedPID)
	}

	var out TerminateProcessResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "ok" || out.PID != 1234 || out.Name != "notepad.exe" {
		t.Fatalf("unexpected terminate_process result: %+v", out)
	}
	if len(out.ReasonSHA256) != 64 {
		t.Fatalf("invalid reason sha256: %s", out.ReasonSHA256)
	}
}

func TestExecuteTerminateProcessProtectedRefusal(t *testing.T) {
	// PIDs 0, 4, selfPID, and protected image names
	cases := []struct {
		pid          int
		resolvedName string
		self         int
	}{
		{0, "idle.exe", 9999},
		{4, "system", 9999},
		{9999, "myagent.exe", 9999},
		{5555, "smss.exe", 9999},
		{5556, "csrss.exe", 9999},
		{5557, "services.exe", 9999},
		{5558, "lsass.exe", 9999},
		{5559, "svchost.exe", 9999},
		{5560, "nodelinkagent.exe", 9999},
		{5561, "NodeLinkAgent.exe", 9999},
	}

	for _, c := range cases {
		calledTerm := false
		withSeams(t, nil, nil, nil,
			func(_ context.Context, _ int) error {
				calledTerm = true
				return nil
			},
			func(_ context.Context, _ int) (string, error) {
				return c.resolvedName, nil
			},
			func() int { return c.self },
		)

		payload := fmt.Sprintf(`{"pid":%d,"confirm":true,"reason":"Valid reason for terminate"}`, c.pid)
		res := Execute(context.Background(), executor.KindTerminateProcess, json.RawMessage(payload))
		if res.ExitCode == 0 {
			t.Fatalf("protected process (pid=%d name=%s) must be refused with exit code 1", c.pid, c.resolvedName)
		}
		if calledTerm {
			t.Fatalf("protected process (pid=%d name=%s) must not invoke terminate seam", c.pid, c.resolvedName)
		}

		var out TerminateProcessResult
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if out.Status != "protected" {
			t.Fatalf("want status protected for pid=%d name=%s, got %s", c.pid, c.resolvedName, out.Status)
		}
	}
}

func TestExecuteTerminateProcessNotFound(t *testing.T) {
	withSeams(t, nil, nil, nil, nil,
		func(_ context.Context, _ int) (string, error) {
			return "", errors.New("process not found")
		},
		func() int { return 9999 },
	)

	payload := `{"pid":8888,"confirm":true,"reason":"Valid reason for terminate"}`
	res := Execute(context.Background(), executor.KindTerminateProcess, json.RawMessage(payload))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for process not found")
	}

	var out TerminateProcessResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "not_found" {
		t.Fatalf("want status not_found, got %s", out.Status)
	}
}

func TestExecuteTerminateProcessNameMismatch(t *testing.T) {
	withSeams(t, nil, nil, nil, nil,
		func(_ context.Context, _ int) (string, error) {
			return "calc.exe", nil
		},
		func() int { return 9999 },
	)

	payload := `{"pid":1234,"expected_name":"notepad.exe","confirm":true,"reason":"Valid reason for terminate"}`
	res := Execute(context.Background(), executor.KindTerminateProcess, json.RawMessage(payload))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for name mismatch")
	}

	var out TerminateProcessResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "name_mismatch" {
		t.Fatalf("want status name_mismatch, got %s", out.Status)
	}
}

func TestExecuteTerminateProcessFailed(t *testing.T) {
	withSeams(t, nil, nil, nil,
		func(_ context.Context, _ int) error {
			return errors.New("access denied")
		},
		func(_ context.Context, _ int) (string, error) {
			return "badapp.exe", nil
		},
		func() int { return 9999 },
	)

	payload := `{"pid":1234,"confirm":true,"reason":"Valid reason for terminate"}`
	res := Execute(context.Background(), executor.KindTerminateProcess, json.RawMessage(payload))
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for terminate failure")
	}

	var out TerminateProcessResult
	if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if out.Status != "failed" || out.Message != "access denied" {
		t.Fatalf("unexpected terminate_process result: %+v", out)
	}
}

func TestExecuteTerminateProcessInvalidPayloads(t *testing.T) {
	cases := []string{
		`{"pid":-5,"confirm":true,"reason":"Valid reason for terminate"}`,
		`{"pid":1234,"confirm":false,"reason":"Valid reason for terminate"}`,
		`{"pid":1234,"confirm":true,"reason":"short"}`,
		`{"pid":1234,"confirm":true,"reason":"invalid reason\x07with control char"}`,
		`{"pid":1234,"expected_name":"bad\x07name","confirm":true,"reason":"Valid reason for terminate"}`,
		`{"pid":1234,"confirm":true,"reason":"Valid reason","extra":true}`,
	}

	for _, payload := range cases {
		res := Execute(context.Background(), executor.KindTerminateProcess, json.RawMessage(payload))
		if res.ExitCode == 0 {
			t.Fatalf("payload should have been rejected: %s", payload)
		}
		var out TerminateProcessResult
		if err := json.Unmarshal([]byte(res.Stdout), &out); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if out.Status != "invalid" {
			t.Fatalf("want status invalid for payload %s, got %s", payload, out.Status)
		}
	}
}

func TestExecuteUnsupportedKind(t *testing.T) {
	res := Execute(context.Background(), "unknown_svcproc_kind", nil)
	if res.ExitCode == 0 {
		t.Fatal("expected exit code 1 for unsupported kind")
	}
}
