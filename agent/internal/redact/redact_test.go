// SPDX-License-Identifier: AGPL-3.0-only

package redact

import (
	"strings"
	"testing"
)

const sentinel = "nlk-SENTINEL-SECRET-do-not-log-4c8f2a"

func TestBearerScrubbed(t *testing.T) {
	out := Text("GET /x: 401 Authorization: Bearer " + sentinel)
	if strings.Contains(out, sentinel) {
		t.Fatalf("bearer token leaked: %q", out)
	}
	if !strings.Contains(out, Redacted) {
		t.Fatalf("expected redaction marker: %q", out)
	}
}

func TestKeyValueSecretsScrubbed(t *testing.T) {
	for _, in := range []string{
		"enrollment_token=" + sentinel,
		`{"agent_token": "` + sentinel + `"}`,
		"passphrase: " + sentinel,
		"api_key=" + sentinel,
	} {
		if out := Text(in); strings.Contains(out, sentinel) {
			t.Fatalf("secret leaked for %q -> %q", in, out)
		}
	}
}

func TestPEMPrivateKeyScrubbed(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2Vw" +
		strings.Repeat("A", 40) + "\n-----END PRIVATE KEY-----"
	if out := Text("dumped key " + pem); strings.Contains(out, "MC4CAQAw") {
		t.Fatalf("PEM key leaked: %q", out)
	}
}

func TestJWTScrubbed(t *testing.T) {
	j := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvcCJ9.abc123DEF456ghi_-jkl"
	if out := Text("token " + j); strings.Contains(out, j) {
		t.Fatalf("JWT leaked: %q", out)
	}
}

func TestOrdinaryTextPreserved(t *testing.T) {
	// Command IDs, nonces, hashes and status codes must survive; they are not
	// secrets and log readers rely on them.
	in := "POST /api/v1/commands/7f3a/result: 404 Command not found"
	if out := Text(in); out != in {
		t.Fatalf("ordinary text altered: %q -> %q", in, out)
	}
}

func TestEmptyString(t *testing.T) {
	if Text("") != "" {
		t.Fatal("empty string should stay empty")
	}
}
