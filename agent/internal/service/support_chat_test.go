// SPDX-License-Identifier: AGPL-3.0-only
package service

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
)

func TestChatURLNeverReachesLogWriter(t *testing.T) {
	const url = "https://support.test/chat#c=one&t=SECRET_CHAT_TOKEN"
	for _, phase := range []string{"success", "create", "launch"} {
		var logs bytes.Buffer
		a := NewAgent("unused", "test", log.New(&logs, "", 0))
		err := a.openSupportChat(context.Background(), func(context.Context) (string, error) {
			if phase == "create" {
				return "", fmt.Errorf("untrusted response: %s", url)
			}
			return url, nil
		}, func(got string) error {
			if got != url {
				t.Fatal("URL changed")
			}
			if phase == "launch" {
				return fmt.Errorf("cannot open %s", url)
			}
			return nil
		})
		if (err == nil) != (phase == "success") {
			t.Fatal("wrong outcome")
		}
		if strings.Contains(logs.String(), url) || strings.Contains(logs.String(), "SECRET_CHAT_TOKEN") {
			t.Fatal("credential reached logger")
		}
	}
}
