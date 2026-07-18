package verify

import (
	"testing"

	"github.com/lcolon231/rmm/agent/internal/protocol"
)

// The expected strings here are produced by Python's
// json.dumps(doc, sort_keys=True, separators=(",", ":")) — see the server's
// canonical_command_bytes. If these ever diverge, signature verification breaks.
func TestCanonicalMatchesPython(t *testing.T) {
	cases := []struct {
		name     string
		cmdID    string
		agentID  string
		kind     string
		payload  string
		expected string
	}{
		{
			name:     "simple script",
			cmdID:    "c1",
			agentID:  "a1",
			kind:     "powershell",
			payload:  `{"script":"Get-Date"}`,
			expected: `{"agent_id":"a1","command_id":"c1","envelope_version":"command-v1","kind":"powershell","payload":{"script":"Get-Date"}}`,
		},
		{
			name:    "script with angle brackets and ampersand",
			cmdID:   "c2",
			agentID: "a2",
			kind:    "powershell",
			// Contains > and & which Go would HTML-escape by default.
			payload:  `{"script":"Get-Process | Where {$_.CPU > 5} & echo done"}`,
			expected: `{"agent_id":"a2","command_id":"c2","envelope_version":"command-v1","kind":"powershell","payload":{"script":"Get-Process | Where {$_.CPU > 5} & echo done"}}`,
		},
		{
			name:     "empty payload",
			cmdID:    "c3",
			agentID:  "a3",
			kind:     "collect_inventory",
			payload:  ``,
			expected: `{"agent_id":"a3","command_id":"c3","envelope_version":"command-v1","kind":"collect_inventory","payload":{}}`,
		},
		{
			name:     "nested keys sorted",
			cmdID:    "c4",
			agentID:  "a4",
			kind:     "shell",
			payload:  `{"zeta":1,"alpha":2}`,
			expected: `{"agent_id":"a4","command_id":"c4","envelope_version":"command-v1","kind":"shell","payload":{"alpha":2,"zeta":1}}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := canonicalCommandBytes(protocol.CommandEnvelopeV1, tc.cmdID, tc.agentID, tc.kind, []byte(tc.payload))
			if err != nil {
				t.Fatalf("canonicalCommandBytes error: %v", err)
			}
			if string(got) != tc.expected {
				t.Errorf("canonical mismatch\n got: %s\nwant: %s", got, tc.expected)
			}
		})
	}
}
