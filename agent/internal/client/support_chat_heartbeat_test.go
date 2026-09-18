// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"encoding/json"
	"testing"
)

func TestHeartbeatAckChatLaunchIsAdditive(t *testing.T) {
	var older HeartbeatAck
	if err := json.Unmarshal([]byte(`{"ok":true,"unknown_future_field":"ignored"}`), &older); err != nil {
		t.Fatal(err)
	}
	if older.ChatLaunchRequested != "" {
		t.Fatalf("omitted chat launch = %q, want empty", older.ChatLaunchRequested)
	}

	const raw = "https://support.test/chat#c=one&t=secret"
	var current HeartbeatAck
	if err := json.Unmarshal([]byte(`{"ok":true,"chat_launch_requested":"`+raw+`"}`), &current); err != nil {
		t.Fatal(err)
	}
	if current.ChatLaunchRequested != raw {
		t.Fatalf("chat launch = %q, want %q", current.ChatLaunchRequested, raw)
	}
}
