//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func osVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

// cpuTimes returns (idle, total) jiffies from /proc/stat.
func cpuTimes() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line := strings.SplitN(string(data), "\n", 2)[0]
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	var vals []uint64
	for _, f := range fields[1:] {
		v, _ := strconv.ParseUint(f, 10, 64)
		vals = append(vals, v)
	}
	for i, v := range vals {
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	return idle, total
}

func collect() Sample {
	// CPU: sample twice over a short interval.
	idle1, total1 := cpuTimes()
	time.Sleep(200 * time.Millisecond)
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

	return Sample{
		CPUPercent:    round2(cpu),
		MemPercent:    round2(mem),
		DiskPercent:   round2(disk),
		UptimeSeconds: uptimeSeconds(),
		LoggedInUser:  os.Getenv("USER"),
	}
}

func meminfo() (total, avail uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	return total, avail
}

func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	f, _ := strconv.ParseFloat(fields[0], 64)
	return int64(f)
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}
