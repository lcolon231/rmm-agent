//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package eventlog

import "testing"

const twoEventsXML = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Level>0</Level><Task>12544</Task><EventRecordID>9001</EventRecordID><Channel>Security</Channel><Computer>PC-EVT</Computer><TimeCreated SystemTime='2026-08-09T12:00:00.000Z'/></System><EventData><Data Name='TargetUserName'>PATIENT_SECRET</Data></EventData></Event>` +
	`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Service Control Manager'/><EventID Qualifiers='16384'>7036</EventID><Level>4</Level><Task>0</Task><EventRecordID>9002</EventRecordID><Channel>System</Channel><Computer>PC-EVT</Computer><TimeCreated SystemTime='2026-08-09T12:01:00.000Z'/></System><EventData><Data>PHI_HERE</Data></EventData></Event>`

func TestParseEventsKeepsSystemDropsEventData(t *testing.T) {
	records, err := parseEvents([]byte(twoEventsXML))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("want 2 records, got %d", len(records))
	}

	first := records[0]
	if first.RecordID != 9001 || first.EventID != 4624 || first.Provider != "Microsoft-Windows-Security-Auditing" || first.Channel != "Security" {
		t.Fatalf("unexpected first record: %+v", first)
	}
	// EventID with a Qualifiers attribute still parses its inner text.
	if records[1].EventID != 7036 || records[1].Provider != "Service Control Manager" {
		t.Fatalf("unexpected second record: %+v", records[1])
	}

	// No EventData value may appear in any reported metadata field.
	for _, record := range records {
		for _, field := range []string{record.Provider, record.Keywords, record.Computer, record.Channel, record.TimeCreated} {
			if field == "PATIENT_SECRET" || field == "PHI_HERE" {
				t.Fatalf("EventData leaked into metadata: %+v", record)
			}
		}
	}
}
