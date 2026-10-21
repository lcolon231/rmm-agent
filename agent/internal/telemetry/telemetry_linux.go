//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"context"
	"os"
	"syscall"
	"time"
)

func osVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return parseOSReleasePrettyName(string(data))
}

// cpuTimes returns (idle, total) jiffies from /proc/stat.
func cpuTimes() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	return parseProcStatCPU(string(data))
}

func collect(ctx context.Context) Sample {
	// CPU: sample twice over a short interval.
	idle1, total1 := cpuTimes()
	timer := time.NewTimer(200 * time.Millisecond)
	select {
	case <-ctx.Done():
		timer.Stop()
		return Sample{}
	case <-timer.C:
	}
	idle2, total2 := cpuTimes()
	cpu := 0.0
	if total2 > total1 {
		idleDelta := float64(idle2 - idle1)
		totalDelta := float64(total2 - total1)
		cpu = (1.0 - idleDelta/totalDelta) * 100.0
	}

	// Memory from /proc/meminfo.
	memTotal, memAvail := meminfo()
	mem := 0.0
	if memTotal > 0 {
		mem = float64(memTotal-memAvail) / float64(memTotal) * 100.0
	}

	// Disk usage of root filesystem.
	var st syscall.Statfs_t
	disk := 0.0
	if err := syscall.Statfs("/", &st); err == nil && st.Blocks > 0 {
		free := st.Bavail * uint64(st.Bsize)
		totalB := st.Blocks * uint64(st.Bsize)
		disk = float64(totalB-free) / float64(totalB) * 100.0
	}

	uptime, uptimeOK := uptimeSeconds()
	return Sample{
		CPUPercent:      round2(cpu),
		MemPercent:      round2(mem),
		DiskPercent:     round2(disk),
		UptimeSeconds:   uptime,
		LoggedInUser:    os.Getenv("USER"),
		CollectedAt:     time.Now().UTC(),
		CPUAvailable:    total2 > total1,
		MemAvailable:    memTotal > 0,
		DiskAvailable:   st.Blocks > 0,
		UptimeAvailable: uptimeOK,
	}
}

func meminfo() (total, avail uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	return parseMeminfo(string(data))
}

func uptimeSeconds() (int64, bool) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, false
	}
	return parseUptime(string(data))
}
