// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"bufio"
	"strconv"
	"strings"
)

// parseLocaleFloat parses PowerShell output that may use a comma decimal
// separator (non-English locales) and surrounding whitespace.
func parseLocaleFloat(out string) (float64, bool) {
	f, err := strconv.ParseFloat(strings.TrimSpace(strings.ReplaceAll(out, ",", ".")), 64)
	return f, err == nil
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

// parseOSReleasePrettyName extracts PRETTY_NAME from /etc/os-release content.
func parseOSReleasePrettyName(data string) string {
	sc := bufio.NewScanner(strings.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

// parseProcStatCPU returns (idle, total) jiffies from /proc/stat content,
// using only the first line. Unparseable fields count as zero.
func parseProcStatCPU(data string) (idle, total uint64) {
	line := strings.SplitN(data, "\n", 2)[0]
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

// parseMeminfo returns MemTotal and MemAvailable (kB) from /proc/meminfo content.
func parseMeminfo(data string) (total, avail uint64) {
	sc := bufio.NewScanner(strings.NewReader(data))
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

// parseUptime returns whole seconds from /proc/uptime content.
func parseUptime(data string) (int64, bool) {
	fields := strings.Fields(data)
	if len(fields) == 0 {
		return 0, false
	}
	f, err := strconv.ParseFloat(fields[0], 64)
	return int64(f), err == nil
}
