//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

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
	return Sample{
		CPUPercent:    round2(cpuPercent(ctx)),
		MemPercent:    round2(memPercent(ctx)),
		DiskPercent:   round2(diskPercent(ctx)),
		UptimeSeconds: uptimeSeconds(ctx),
		LoggedInUser:  loggedInUser(ctx),
	}
}

func psOutput(ctx context.Context, script string) (string, error) {
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	return string(out), err
}

func psFloat(ctx context.Context, script string) float64 {
	out, err := psOutput(ctx, script)
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.TrimSpace(strings.ReplaceAll(out, ",", ".")), 64)
	return f
}

func cpuPercent(ctx context.Context) float64 {
	return psFloat(ctx, `(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average`)
}

func memPercent(ctx context.Context) float64 {
	return psFloat(ctx, `$o=Get-CimInstance Win32_OperatingSystem; ` +
		`[math]::Round((($o.TotalVisibleMemorySize - $o.FreePhysicalMemory) / $o.TotalVisibleMemorySize) * 100, 2)`)
}

func diskPercent(ctx context.Context) float64 {
	return psFloat(ctx, `$d=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"; ` +
		`[math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 2)`)
}

func uptimeSeconds(ctx context.Context) int64 {
	f := psFloat(ctx, `[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds`)
	return int64(f)
}

func loggedInUser(ctx context.Context) string {
	out, err := psOutput(ctx, `(Get-CimInstance Win32_ComputerSystem).UserName`)
	if err != nil {
		return os.Getenv("USERNAME")
	}
	return strings.TrimSpace(out)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
