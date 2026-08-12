// SPDX-License-Identifier: AGPL-3.0-only

package patching

import (
	"encoding/json"
	"testing"
)

// The stdout an agent captured when the update downloader's COM return value was
// left on the pipeline: PowerShell's formatter wrote the IDownloadResult table
// ahead of the JSON, so the whole-buffer unmarshal failed on 'H' and a completed
// install was reported as a failure.
const downloaderNoiseStdout = "\r\nHResult ResultCode\r\n------- ----------\r\n" +
	"      0          2\r\n" +
	`{"status":"success","installed_kbs":["KB5122104"],"failed_kbs":[],` +
	`"results":[{"identifier":"KB5122104","result_code":2,"hresult":"0x00000000"}],` +
	`"reboot_required":false,"message":"Installed 1 update(s), 0 failed."}` + "\r\n\r\n\r\n"

func TestExtractPSJSONRecoversInstallResultAfterFormatterNoise(t *testing.T) {
	var res InstallResult
	if err := json.Unmarshal(extractPSJSON([]byte(downloaderNoiseStdout)), &res); err != nil {
		t.Fatalf("unmarshal after extraction: %v", err)
	}
	if res.Status != "success" {
		t.Fatalf("status = %q, want success", res.Status)
	}
	if len(res.InstalledKBs) != 1 || res.InstalledKBs[0] != "KB5122104" {
		t.Fatalf("installed_kbs = %v, want [KB5122104]", res.InstalledKBs)
	}
	if len(res.Results) != 1 || res.Results[0].ResultCode != 2 {
		t.Fatalf("results = %+v, want one entry with result_code 2", res.Results)
	}
}

func TestExtractPSJSON(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"clean payload", `{"status":"success"}`, `{"status":"success"}`},
		{"crlf wrapped", "\r\n" + `{"a":1}` + "\r\n", `{"a":1}`},
		{"leading noise", "WARNING: something\n" + `{"a":1}`, `{"a":1}`},
		{"trailing noise", `{"a":1}` + "\nVERBOSE: done\n", `{"a":1}`},
		{
			// Only the final document is the collector's result; an earlier
			// object in the stream must not win.
			"last object wins",
			`{"a":1}` + "\n" + `{"a":2}`,
			`{"a":2}`,
		},
		{
			// A brace-led line that is not valid JSON is skipped rather than
			// returned as the payload.
			"skips invalid brace line",
			`{not json` + "\n" + `{"a":1}` + "\n" + `{also not json`,
			`{"a":1}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(extractPSJSON([]byte(tc.stdout))); got != tc.want {
				t.Fatalf("extractPSJSON() = %q, want %q", got, tc.want)
			}
		})
	}
}

// No JSON object at all leaves stdout untouched so the caller's error message
// still quotes what PowerShell actually wrote.
func TestExtractPSJSONWithoutObjectReturnsInput(t *testing.T) {
	stdout := "Access is denied.\r\n"
	if got := string(extractPSJSON([]byte(stdout))); got != stdout {
		t.Fatalf("extractPSJSON() = %q, want the input unchanged", got)
	}
}
