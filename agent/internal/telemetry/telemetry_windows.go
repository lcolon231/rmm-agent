//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/lcolon231/rmm/agent/internal/pwsh"
)

// psTimeout bounds each CIM query so a wedged provider cannot stall the
// heartbeat that collects the sample.
const psTimeout = 15 * time.Second

// osVersion returns the Windows product name and build.
func osVersion() string {
	out, err := psOutput(context.Background(), `(Get-CimInstance Win32_OperatingSystem).Version`)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// collect gathers metrics using PowerShell CIM queries. This avoids external
// Go dependencies at the cost of spawning powershell.exe per sample, which is
// acceptable at a 60s cadence. A future optimization is to call the Win32 APIs
// directly via golang.org/x/sys/windows.
func collect(ctx context.Context) Sample {
	cpu, cpuOK := cpuPercent(ctx)
	mem, memOK := memPercent(ctx)
	disk, diskOK := diskPercent(ctx)
	uptime, uptimeOK := uptimeSeconds(ctx)
	return Sample{
		CPUPercent:      round2(cpu),
		MemPercent:      round2(mem),
		DiskPercent:     round2(disk),
		UptimeSeconds:   uptime,
		LoggedInUser:    loggedInUser(ctx),
		CollectedAt:     time.Now().UTC(),
		CPUAvailable:    cpuOK,
		MemAvailable:    memOK,
		DiskAvailable:   diskOK,
		UptimeAvailable: uptimeOK,
	}
}

// runPS is a var so tests can substitute a fake.
var runPS pwsh.Runner = pwsh.Exec

// psOutput runs a PowerShell script and returns its stdout.
func psOutput(ctx context.Context, script string) (string, error) {
	res, err := runPS(ctx, pwsh.Script{Body: script, Timeout: psTimeout})
	return string(res.Stdout), err
}

func psFloat(ctx context.Context, script string) (float64, bool) {
	out, err := psOutput(ctx, script)
	if err != nil {
		return 0, false
	}
	return parseLocaleFloat(out)
}

func cpuPercent(ctx context.Context) (float64, bool) {
	return psFloat(ctx, `(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average`)
}

func memPercent(ctx context.Context) (float64, bool) {
	return psFloat(ctx, `$o=Get-CimInstance Win32_OperatingSystem; `+
		`[math]::Round((($o.TotalVisibleMemorySize - $o.FreePhysicalMemory) / $o.TotalVisibleMemorySize) * 100, 2)`)
}

func diskPercent(ctx context.Context) (float64, bool) {
	return psFloat(ctx, `$d=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"; `+
		`[math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 2)`)
}

func uptimeSeconds(ctx context.Context) (int64, bool) {
	f, ok := psFloat(ctx, `[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds`)
	return int64(f), ok
}

func loggedInUser(ctx context.Context) string {
	out, err := psOutput(ctx, `(Get-CimInstance Win32_ComputerSystem).UserName`)
	if err != nil {
		return os.Getenv("USERNAME")
	}
	return strings.TrimSpace(out)
}
