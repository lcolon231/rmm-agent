// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import "testing"

func TestParseLocaleFloat(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want float64
		ok   bool
	}{
		{"dot", "12.5\r\n", 12.5, true},
		{"comma locale", "12,5", 12.5, true},
		{"whitespace", "  \t42 \n", 42, true},
		{"integer", "7", 7, true},
		{"empty", "", 0, false},
		{"only space", "  \n", 0, false},
		{"garbage", "abc", 0, false},
		{"thousands ambiguity", "1,234,5", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseLocaleFloat(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("parseLocaleFloat(%q) = %v,%v want %v,%v", tt.in, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestRound2(t *testing.T) {
	tests := []struct{ in, want float64 }{
		{0, 0}, {12.344, 12.34}, {12.346, 12.35}, {99.999, 100}, {0.004, 0},
	}
	for _, tt := range tests {
		if got := round2(tt.in); got != tt.want {
			t.Errorf("round2(%v) = %v want %v", tt.in, got, tt.want)
		}
	}
}

func TestParseOSReleasePrettyName(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"quoted", "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nID=ubuntu\n", "Ubuntu 22.04.3 LTS"},
		{"unquoted", "ID=arch\nPRETTY_NAME=Arch Linux\n", "Arch Linux"},
		{"missing", "NAME=\"x\"\nID=x\n", ""},
		{"empty", "", ""},
		{"empty value", "PRETTY_NAME=\n", ""},
		{"not a prefix match", "XPRETTY_NAME=\"no\"\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseOSReleasePrettyName(tt.in); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseProcStatCPU(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		idle, total uint64
	}{
		{"typical", "cpu  100 20 30 400 50 6 7 8 0 0\ncpu0 1 2 3 4 5\n", 450, 621},
		{"no newline", "cpu 1 1 1 1 1", 2, 5},
		{"too few fields", "cpu 1 2 3\n", 0, 0},
		{"wrong label", "cpu0 1 2 3 4 5\n", 0, 0},
		{"empty", "", 0, 0},
		{"garbage field counts as zero", "cpu 10 x 10 10 10\n", 20, 40},
		{"only first line used", "intr 1 2 3 4 5\ncpu 1 1 1 1 1\n", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idle, total := parseProcStatCPU(tt.in)
			if idle != tt.idle || total != tt.total {
				t.Fatalf("got %d,%d want %d,%d", idle, total, tt.idle, tt.total)
			}
		})
	}
}

func TestParseMeminfo(t *testing.T) {
	tests := []struct {
		name         string
		in           string
		total, avail uint64
	}{
		{"typical", "MemTotal:       16318480 kB\nMemFree:         1000 kB\nMemAvailable:    8000000 kB\n", 16318480, 8000000},
		{"missing MemAvailable", "MemTotal: 1000 kB\nMemFree: 10 kB\n", 1000, 0},
		{"short and blank lines", "\nfoo\nMemTotal: 5 kB\n", 5, 0},
		{"garbage value", "MemTotal: abc kB\nMemAvailable: 3 kB\n", 0, 3},
		{"empty", "", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			total, avail := parseMeminfo(tt.in)
			if total != tt.total || avail != tt.avail {
				t.Fatalf("got %d,%d want %d,%d", total, avail, tt.total, tt.avail)
			}
		})
	}
}

func TestParseUptime(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want int64
		ok   bool
	}{
		{"typical", "12345.67 54321.00\n", 12345, true},
		{"single field", "99.9", 99, true},
		{"empty", "", 0, false},
		{"whitespace", " \n", 0, false},
		{"garbage", "abc 1\n", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseUptime(tt.in)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("got %d,%v want %d,%v", got, ok, tt.want, tt.ok)
			}
		})
	}
}
