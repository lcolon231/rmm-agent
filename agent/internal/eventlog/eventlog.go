// SPDX-License-Identifier: AGPL-3.0-only
// Package eventlog implements the bounded, metadata-only Windows event log query
// introduced by issue #58. It returns structured <System> metadata only — never
// the rendered message, <EventData>, or <UserData> — so no PHI-bearing free text
// ever crosses the wire or is stored. The server has already validated the
// channel allowlist, tier acknowledgment, filters, and bounds; the agent
// re-validates structurally and enforces the same caps at the endpoint.
package eventlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/lcolon231/rmm/agent/internal/executor"
)

// queryTimeoutSeconds bounds a single wevtutil invocation.
const queryTimeoutSeconds = 30

type queryPayload struct {
	Channel           string   `json:"channel"`
	TierAck           bool     `json:"tier_ack"`
	TimeWindowSeconds int      `json:"time_window_seconds"`
	Providers         []string `json:"providers"`
	Levels            []int    `json:"levels"`
	EventIDs          []int    `json:"event_ids"`
	MaxEvents         int      `json:"max_events"`
	Cursor            int64    `json:"cursor"`
}

// Record is the metadata-only projection of one event's <System> element.
type Record struct {
	RecordID    int64  `json:"record_id"`
	TimeCreated string `json:"time_created"`
	Provider    string `json:"provider"`
	EventID     int    `json:"event_id"`
	Level       int    `json:"level"`
	Task        int    `json:"task"`
	Keywords    string `json:"keywords,omitempty"`
	Computer    string `json:"computer,omitempty"`
	Channel     string `json:"channel"`
}

// Result is the JSON body reported in the command's stdout. It carries only
// structured metadata plus the pagination watermark.
type Result struct {
	Status     string   `json:"status"`
	Channel    string   `json:"channel"`
	Records    []Record `json:"records"`
	Count      int      `json:"count"`
	NextCursor int64    `json:"next_cursor,omitempty"`
	HasMore    bool     `json:"has_more"`
	Message    string   `json:"message,omitempty"`
}

// runQuery is a seam so tests can substitute the platform query and never shell
// out to wevtutil.
var runQuery = platformQuery

func decodeStrict(raw json.RawMessage, target any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func resultError(status, message string) executor.Result {
	out, _ := json.Marshal(Result{Status: status, Records: []Record{}, Message: message})
	return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: message}
}

// buildXPath assembles the event-log XPath from the validated filters. Every
// value is numeric except provider names, which the server constrains to a safe
// character set and which Execute additionally rejects if they contain quotes.
func buildXPath(p queryPayload) string {
	conds := []string{
		fmt.Sprintf("TimeCreated[timediff(@SystemTime) <= %d]", int64(p.TimeWindowSeconds)*1000),
	}
	if len(p.Levels) > 0 {
		parts := make([]string, 0, len(p.Levels))
		for _, lvl := range p.Levels {
			parts = append(parts, fmt.Sprintf("Level=%d", lvl))
		}
		conds = append(conds, "("+strings.Join(parts, " or ")+")")
	}
	if len(p.EventIDs) > 0 {
		parts := make([]string, 0, len(p.EventIDs))
		for _, id := range p.EventIDs {
			parts = append(parts, fmt.Sprintf("EventID=%d", id))
		}
		conds = append(conds, "("+strings.Join(parts, " or ")+")")
	}
	if len(p.Providers) > 0 {
		parts := make([]string, 0, len(p.Providers))
		for _, name := range p.Providers {
			parts = append(parts, fmt.Sprintf("Provider[@Name='%s']", name))
		}
		conds = append(conds, "("+strings.Join(parts, " or ")+")")
	}
	if p.Cursor > 0 {
		conds = append(conds, fmt.Sprintf("EventRecordID > %d", p.Cursor))
	}
	return "*[System[" + strings.Join(conds, " and ") + "]]"
}

// Execute runs one bounded event log query and returns metadata-only evidence.
func Execute(ctx context.Context, kind string, raw json.RawMessage) executor.Result {
	if kind != executor.KindQueryEventLog {
		return resultError("unsupported", "unsupported event log operation")
	}
	var p queryPayload
	if err := decodeStrict(raw, &p); err != nil {
		return resultError("invalid", "event log query payload is invalid")
	}
	if p.Channel == "" || p.TimeWindowSeconds <= 0 || p.MaxEvents <= 0 {
		return resultError("invalid", "event log query payload is incomplete")
	}
	for _, name := range p.Providers {
		if strings.ContainsAny(name, "'\"") {
			return resultError("invalid", "event log provider name is invalid")
		}
	}

	// Request one extra event so a full page can be distinguished from the end
	// of the log without a second round trip.
	records, err := runQuery(ctx, p.Channel, buildXPath(p), p.MaxEvents+1)
	if err != nil {
		out, _ := json.Marshal(Result{Status: "failed", Channel: p.Channel, Records: []Record{}, Message: "event log query failed"})
		return executor.Result{ExitCode: 1, Stdout: string(out), Stderr: err.Error()}
	}

	hasMore := false
	if len(records) > p.MaxEvents {
		records = records[:p.MaxEvents]
		hasMore = true
	}
	if records == nil {
		records = []Record{}
	}
	var nextCursor int64
	for _, r := range records {
		if r.RecordID > nextCursor {
			nextCursor = r.RecordID
		}
	}

	result := Result{
		Status:  "ok",
		Channel: p.Channel,
		Records: records,
		Count:   len(records),
		HasMore: hasMore,
	}
	if len(records) > 0 {
		result.NextCursor = nextCursor
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return executor.Result{ExitCode: -1, Stderr: "event log query failed: encode result"}
	}
	return executor.Result{ExitCode: 0, Stdout: string(encoded), StdoutTotalBytes: int64(len(encoded))}
}
