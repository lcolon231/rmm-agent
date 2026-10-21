// SPDX-License-Identifier: AGPL-3.0-only

package inventory

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

type row = map[string]any

// wireJSON renders a payload the way the inventory hash sees it: encoding/json
// sorts map keys, so the string is a stable pin of the exact section output.
func wireJSON(t *testing.T, payload map[string]any) string {
	t.Helper()
	if payload == nil {
		return "null"
	}
	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(out)
}

func TestPutHelpers(t *testing.T) {
	m := map[string]any{}
	putStr(m, "s", "x")
	putStr(m, "empty", "")
	putStr(m, "wrongtype", 5.0)
	putStr(m, "nil", nil)
	putNum(m, "f", 12.9)
	putNum(m, "str", "9007199254740993")
	putNum(m, "badstr", "abc")
	putNum(m, "bool", true)
	putBool(m, "b", false)
	putBool(m, "notbool", "true")
	want := map[string]any{"s": "x", "f": int64(12), "str": int64(9007199254740993), "b": false}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("got %#v want %#v", m, want)
	}
}

func TestFirstAndBoundedStatus(t *testing.T) {
	if first(nil) != nil || first([]row{}) != nil {
		t.Fatal("first of empty must be nil")
	}
	if got := first([]row{{"a": 1}, {"a": 2}}); got["a"] != 1 {
		t.Fatalf("got %v", got)
	}
	if boundedStatus(3, 3) != StatusOK || boundedStatus(4, 3) != StatusPartial {
		t.Fatal("boundedStatus boundary wrong")
	}
}

func TestCPUArchitecture(t *testing.T) {
	tests := map[int]string{0: "x86", 5: "arm", 6: "ia64", 9: "x64", 12: "arm64", 1: "unknown", -1: "unknown", 99: "unknown"}
	for code, want := range tests {
		if got := cpuArchitecture(code); got != want {
			t.Errorf("cpuArchitecture(%d) = %q want %q", code, got, want)
		}
	}
}

func TestNormalizeSystem(t *testing.T) {
	tests := []struct {
		name       string
		rows       []map[string]any
		wantJSON   string
		wantStatus string
	}{
		{"nil rows", nil, "null", StatusUnavailable},
		{"empty rows", []row{}, "null", StatusUnavailable},
		{
			"full",
			[]row{{"Manufacturer": "Dell Inc.", "Model": "XPS", "Serial": "ABC123", "Chassis": "10",
				"BiosVendor": "Dell", "BiosVersion": "1.2.3", "BiosReleaseDate": "2024-01-02T00:00:00.0000000Z"}},
			`{"bios_release_date":"2024-01-02T00:00:00.0000000Z","bios_vendor":"Dell","bios_version":"1.2.3","chassis":"10","manufacturer":"Dell Inc.","model":"XPS","serial":"ABC123"}`,
			StatusOK,
		},
		{"partial with nulls", []row{{"Manufacturer": "ACME", "Model": nil, "Serial": ""}}, `{"manufacturer":"ACME"}`, StatusOK},
		{"all absent", []row{{"Manufacturer": nil, "Model": ""}}, `{}`, StatusUnavailable},
		{"only first row used", []row{{"Model": "A"}, {"Model": "B"}}, `{"model":"A"}`, StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, status := NormalizeSystem(tt.rows)
			if got := wireJSON(t, payload); got != tt.wantJSON || status != tt.wantStatus {
				t.Fatalf("got %s/%s want %s/%s", got, status, tt.wantJSON, tt.wantStatus)
			}
		})
	}
}

func TestNormalizeCPU(t *testing.T) {
	tests := []struct {
		name       string
		rows       []map[string]any
		wantJSON   string
		wantStatus string
	}{
		{"nil rows", nil, "null", StatusUnavailable},
		{
			"full",
			[]row{{"Name": "Intel(R) Core(TM) i7", "Architecture": float64(9), "NumberOfCores": float64(8),
				"NumberOfLogicalProcessors": float64(16), "MaxClockSpeed": float64(3600)}},
			`{"architecture":"x64","logical_cores":16,"max_clock_mhz":3600,"name":"Intel(R) Core(TM) i7","physical_cores":8}`,
			StatusOK,
		},
		{"x86 zero arch", []row{{"Architecture": float64(0)}}, `{"architecture":"x86"}`, StatusOK},
		{"unknown arch", []row{{"Architecture": float64(42)}}, `{"architecture":"unknown"}`, StatusOK},
		{"arch wrong type ignored", []row{{"Architecture": "9"}}, `{}`, StatusUnavailable},
		{"empty row", []row{{}}, `{}`, StatusUnavailable},
		{"string numerics", []row{{"NumberOfCores": "4"}}, `{"physical_cores":4}`, StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, status := NormalizeCPU(tt.rows)
			if got := wireJSON(t, payload); got != tt.wantJSON || status != tt.wantStatus {
				t.Fatalf("got %s/%s want %s/%s", got, status, tt.wantJSON, tt.wantStatus)
			}
		})
	}
}

func TestNormalizeMemory(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		payload, status := NormalizeMemory(
			[]row{{"TotalPhysicalMemory": "17179869184"}},
			[]row{
				{"Capacity": "8589934592", "Speed": float64(3200), "DeviceLocator": "DIMM A", "Manufacturer": "Samsung", "PartNumber": "M471"},
				{"Capacity": "8589934592", "Speed": nil, "DeviceLocator": "DIMM B", "Manufacturer": "", "PartNumber": nil},
			})
		want := `{"modules":[{"capacity_bytes":8589934592,"manufacturer":"Samsung","part_number":"M471","slot":"DIMM A","speed_mhz":3200},{"capacity_bytes":8589934592,"slot":"DIMM B"}],"total_bytes":17179869184}`
		if got := wireJSON(t, payload); got != want || status != StatusOK {
			t.Fatalf("got %s/%s", got, status)
		}
	})
	t.Run("no data still emits empty modules", func(t *testing.T) {
		payload, status := NormalizeMemory(nil, nil)
		if got := wireJSON(t, payload); got != `{"modules":[]}` || status != StatusOK {
			t.Fatalf("got %s/%s", got, status)
		}
	})
	t.Run("modules bounded and partial", func(t *testing.T) {
		mods := make([]map[string]any, MaxMemoryModules+3)
		for i := range mods {
			mods[i] = row{"DeviceLocator": fmt.Sprintf("slot%d", i)}
		}
		payload, status := NormalizeMemory(nil, mods)
		if status != StatusPartial {
			t.Fatalf("status = %s", status)
		}
		if n := len(payload["modules"].([]map[string]any)); n != MaxMemoryModules {
			t.Fatalf("modules = %d", n)
		}
	})
	t.Run("exactly at limit is ok", func(t *testing.T) {
		mods := make([]map[string]any, MaxMemoryModules)
		for i := range mods {
			mods[i] = row{}
		}
		if _, status := NormalizeMemory(nil, mods); status != StatusOK {
			t.Fatalf("status = %s", status)
		}
	})
}

func TestNormalizeStorage(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		payload, status := NormalizeStorage(
			[]row{{"Model": "Samsung SSD", "SerialNumber": "S1", "Size": "512110190592", "MediaType": "Fixed hard disk media", "InterfaceType": "SCSI"}},
			[]row{{"DeviceID": "C:", "VolumeName": "", "FileSystem": "NTFS", "Size": "511", "FreeSpace": "100"}})
		want := `{"disks":[{"bus_type":"SCSI","media_type":"Fixed hard disk media","model":"Samsung SSD","serial":"S1","size_bytes":512110190592}],"volumes":[{"filesystem":"NTFS","free_bytes":100,"mount_point":"C:","size_bytes":511}]}`
		if got := wireJSON(t, payload); got != want || status != StatusOK {
			t.Fatalf("got %s/%s", got, status)
		}
	})
	t.Run("empty", func(t *testing.T) {
		payload, status := NormalizeStorage(nil, nil)
		if got := wireJSON(t, payload); got != `{"disks":[],"volumes":[]}` || status != StatusOK {
			t.Fatalf("got %s/%s", got, status)
		}
	})
	t.Run("bounds", func(t *testing.T) {
		tests := []struct {
			name           string
			disks, volumes int
			wantStatus     string
		}{
			{"disks over", MaxDisks + 1, 0, StatusPartial},
			{"volumes over", 0, MaxVolumes + 1, StatusPartial},
			{"both at limit", MaxDisks, MaxVolumes, StatusOK},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				d := make([]map[string]any, tt.disks)
				v := make([]map[string]any, tt.volumes)
				for i := range d {
					d[i] = row{}
				}
				for i := range v {
					v[i] = row{}
				}
				payload, status := NormalizeStorage(d, v)
				if status != tt.wantStatus {
					t.Fatalf("status = %s", status)
				}
				if n := len(payload["disks"].([]map[string]any)); n > MaxDisks {
					t.Fatalf("disks = %d", n)
				}
				if n := len(payload["volumes"].([]map[string]any)); n > MaxVolumes {
					t.Fatalf("volumes = %d", n)
				}
			})
		}
	})
}

func TestNormalizeNetwork(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		payload, status := NormalizeNetwork([]map[string]any{{
			"Name": "Ethernet", "Mac": "AA:BB:CC:DD:EE:FF", "AdapterType": "Ethernet 802.3",
			"Speed": "1000000000", "Dhcp": true,
			"Addresses": []any{"192.168.1.5", "", 7.0, "fe80::1"},
		}, {
			"Name": "Wi-Fi", "Dhcp": nil, "Addresses": nil,
		}})
		want := `{"adapters":[{"adapter_type":"Ethernet 802.3","addresses":["192.168.1.5","fe80::1"],"dhcp_enabled":true,"mac_address":"AA:BB:CC:DD:EE:FF","name":"Ethernet","speed_bps":1000000000},{"addresses":[],"name":"Wi-Fi"}]}`
		if got := wireJSON(t, payload); got != want || status != StatusOK {
			t.Fatalf("got %s/%s", got, status)
		}
	})
	t.Run("dhcp false is kept", func(t *testing.T) {
		payload, _ := NormalizeNetwork([]map[string]any{{"Dhcp": false}})
		if got := wireJSON(t, payload); got != `{"adapters":[{"addresses":[],"dhcp_enabled":false}]}` {
			t.Fatalf("got %s", got)
		}
	})
	t.Run("empty", func(t *testing.T) {
		payload, status := NormalizeNetwork(nil)
		if got := wireJSON(t, payload); got != `{"adapters":[]}` || status != StatusOK {
			t.Fatalf("got %s/%s", got, status)
		}
	})
	t.Run("adapters bounded", func(t *testing.T) {
		rows := make([]map[string]any, MaxNetworkAdapters+1)
		for i := range rows {
			rows[i] = row{}
		}
		payload, status := NormalizeNetwork(rows)
		if status != StatusPartial || len(payload["adapters"].([]map[string]any)) != MaxNetworkAdapters {
			t.Fatalf("status = %s", status)
		}
	})
	t.Run("addresses bounded", func(t *testing.T) {
		addrs := make([]any, MaxAddressesPerAdapter+2)
		for i := range addrs {
			addrs[i] = fmt.Sprintf("10.0.0.%d", i)
		}
		payload, status := NormalizeNetwork([]map[string]any{{"Addresses": addrs}})
		got := payload["adapters"].([]map[string]any)[0]["addresses"].([]string)
		if status != StatusPartial || len(got) != MaxAddressesPerAdapter {
			t.Fatalf("status = %s, addresses = %d", status, len(got))
		}
	})
}
