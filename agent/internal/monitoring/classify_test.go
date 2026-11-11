// SPDX-License-Identifier: AGPL-3.0-only
package monitoring

import "testing"

func TestClassifyNumeric(t *testing.T) {
	cases := []struct {
		name      string
		value     float64
		threshold Threshold
		want      string
	}{
		{"gt critical", 91, Threshold{Op: "gt", Warning: number(80), Critical: number(90)}, "critical"},
		{"gt at bound is not breached", 90, Threshold{Op: "gt", Critical: number(90)}, "ok"},
		{"gte at bound", 90, Threshold{Op: "gte", Critical: number(90)}, "critical"},
		{"gte warning only", 85, Threshold{Op: "gte", Warning: number(80), Critical: number(90)}, "warning"},
		{"lt critical", 5, Threshold{Op: "lt", Warning: number(20), Critical: number(10)}, "critical"},
		{"lt warning", 15, Threshold{Op: "lt", Warning: number(20), Critical: number(10)}, "warning"},
		{"lte at bound", 10, Threshold{Op: "lte", Critical: number(10)}, "critical"},
		{"lte clear", 11, Threshold{Op: "lte", Critical: number(10)}, "ok"},
		{"no bounds", 1e9, Threshold{Op: "gt"}, "ok"},
		{"unknown op never breaches", 1e9, Threshold{Op: "eq", Critical: number(0)}, "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyNumeric(tc.value, tc.threshold); got != tc.want {
				t.Fatalf("classifyNumeric(%v, %+v) = %q, want %q", tc.value, tc.threshold, got, tc.want)
			}
		})
	}
}

func TestNewEvaluatorDefaultsToPlatformProbe(t *testing.T) {
	e := NewEvaluator(&Store{}, nil)
	if _, ok := e.probe.(platformProbe); !ok {
		t.Fatalf("NewEvaluator(nil probe) used %T, want platformProbe", e.probe)
	}
}
