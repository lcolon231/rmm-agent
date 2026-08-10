//go:build windows

// SPDX-License-Identifier: AGPL-3.0-only
package eventlog

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// xmlEvent maps only the <System> element. <EventData>/<UserData> and any
// rendered message are intentionally absent from this struct, so even though
// wevtutil emits them they are never parsed, retained, or reported. This is the
// metadata-only guarantee that keeps PHI-bearing free text on the endpoint.
type xmlEvent struct {
	System xmlSystem `xml:"System"`
}

type xmlSystem struct {
	Provider struct {
		Name string `xml:"Name,attr"`
	} `xml:"Provider"`
	EventID     int    `xml:"EventID"`
	Level       int    `xml:"Level"`
	Task        int    `xml:"Task"`
	Keywords    string `xml:"Keywords"`
	TimeCreated struct {
		SystemTime string `xml:"SystemTime,attr"`
	} `xml:"TimeCreated"`
	EventRecordID int64  `xml:"EventRecordID"`
	Channel       string `xml:"Channel"`
	Computer      string `xml:"Computer"`
}

func platformQuery(ctx context.Context, channel, xpath string, limit int) ([]Record, error) {
	bounded, cancel := context.WithTimeout(ctx, queryTimeoutSeconds*time.Second)
	defer cancel()
	args := []string{
		"qe", channel,
		"/q:" + xpath,
		"/c:" + strconv.Itoa(limit),
		"/rd:false", // oldest-first, so EventRecordID advances with the cursor
		"/f:XML",    // raw event XML (no rendered message strings)
	}
	out, err := exec.CommandContext(bounded, "wevtutil.exe", args...).Output()
	if err != nil {
		stderr := ""
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = strings.TrimSpace(string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("wevtutil query failed: %w: %s", err, stderr)
	}
	return parseEvents(out)
}

// parseEvents decodes the concatenated <Event> elements wevtutil emits, keeping
// only the <System> projection.
func parseEvents(data []byte) ([]Record, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var records []Record
	for {
		var ev xmlEvent
		err := dec.Decode(&ev)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse event xml: %w", err)
		}
		records = append(records, Record{
			RecordID:    ev.System.EventRecordID,
			TimeCreated: ev.System.TimeCreated.SystemTime,
			Provider:    ev.System.Provider.Name,
			EventID:     ev.System.EventID,
			Level:       ev.System.Level,
			Task:        ev.System.Task,
			Keywords:    ev.System.Keywords,
			Computer:    ev.System.Computer,
			Channel:     ev.System.Channel,
		})
	}
	return records, nil
}
