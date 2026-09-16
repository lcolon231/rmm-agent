// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSupportChatUsesAgentCredentialAndSuppressesResponseErrors(t *testing.T) {
	for _, status := range []int{200, 500} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/api/v1/support/agent/conversations" || r.Header.Get("Authorization") != "Bearer agent-token" {
				t.Error("wrong contract")
			}
			w.WriteHeader(status)
			fmt.Fprint(w, `{"url":"https://support.test/chat#t=SECRET"}`)
		}))
		raw, err := New(server.URL, "agent-token").OpenSupportChat(context.Background())
		server.Close()
		if status == 200 && (err != nil || raw != "https://support.test/chat#t=SECRET") {
			t.Fatal("bad success")
		}
		if status == 500 && (err == nil || strings.Contains(err.Error(), "SECRET")) {
			t.Fatal("response credential leaked")
		}
	}
}
