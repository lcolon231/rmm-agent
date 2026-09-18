// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
)

func TestHeartbeatChatLaunchDeduplicatesAndNeverLogsURL(t *testing.T) {
	const raw = "https://support.test/chat#c=one&t=SECRET_HEARTBEAT_TOKEN"
	var logs bytes.Buffer
	a := NewAgent("unused", "test", log.New(&logs, "", 0))
	launches := 0
	a.openChatURL = func(got string) error {
		launches++
		if got != raw {
			t.Fatalf("URL changed: %q", got)
		}
		return nil
	}

	a.handleChatLaunch(raw)
	a.handleChatLaunch(raw)
	if launches != 1 {
		t.Fatalf("launches = %d, want 1", launches)
	}
	a.handleChatLaunch("")
	a.handleChatLaunch(raw)
	if launches != 2 {
		t.Fatalf("launches after clear = %d, want 2", launches)
	}
	if strings.Contains(logs.String(), raw) || strings.Contains(logs.String(), "SECRET_HEARTBEAT_TOKEN") {
		t.Fatal("credential reached logger")
	}
}

func TestHeartbeatChatLaunchRetriesAfterFailure(t *testing.T) {
	a := NewAgent("unused", "test", log.New(&bytes.Buffer{}, "", 0))
	attempts := 0
	a.openChatURL = func(string) error {
		attempts++
		if attempts == 1 {
			return errors.New("launch failed")
		}
		return nil
	}
	a.handleChatLaunch("https://support.test/chat#one")
	a.handleChatLaunch("https://support.test/chat#one")
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}
