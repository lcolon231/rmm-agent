//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// osVersion returns the Windows product name and build.
func osVersion() string {
	out, err := psOutput(`(Get-CimInstance Win32_OperatingSystem).Version`)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// collect gathers metrics using PowerShell CIM queries. This avoids external
// Go dependencies at the cost of spawning powershell.exe per sample, which is
// acceptable at a 60s cadence. A future optimization is to call the Win32 APIs
// directly via golang.org/x/sys/windows.
func collect() Sample {
	return Sample{
		CPUPercent:    round2(cpuPercent()),
		MemPercent:    round2(memPercent()),
		DiskPercent:   round2(diskPercent()),
		UptimeSeconds: uptimeSeconds(),
		LoggedInUser:  loggedInUser(),
	}
}

func psOutput(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", script)
	out, err := cmd.Output()
	return string(out), err
}

func psFloat(script string) float64 {
	out, err := psOutput(script)
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.TrimSpace(strings.ReplaceAll(out, ",", ".")), 64)
	return f
}

func cpuPercent() float64 {
	return psFloat(`(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average`)
}

func memPercent() float64 {
	return psFloat(`$o=Get-CimInstance Win32_OperatingSystem; ` +
		`[math]::Round((($o.TotalVisibleMemorySize - $o.FreePhysicalMemory) / $o.TotalVisibleMemorySize) * 100, 2)`)
}

func diskPercent() float64 {
	return psFloat(`$d=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"; ` +
		`[math]::Round((($d.Size - $d.FreeSpace) / $d.Size) * 100, 2)`)
}

func uptimeSeconds() int64 {
	f := psFloat(`[int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalSeconds`)
	return int64(f)
}

func loggedInUser() string {
	out, err := psOutput(`(Get-CimInstance Win32_ComputerSystem).UserName`)
	if err != nil {
		return os.Getenv("USERNAME")
	}
	return strings.TrimSpace(out)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
