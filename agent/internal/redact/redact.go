// SPDX-License-Identifier: AGPL-3.0-only

// Package redact scrubs credential-shaped substrings out of free text before it
// reaches a log line or an error message (issue #112).
//
// The agent handles several secrets: its bearer/agent token, the one-time
// enrollment token, and (transiently) the DPAPI-unwrapped identity. Those are
// never deliberately logged, but server error bodies and wrapped errors are, so
// this package is the defensive boundary applied where untrusted or
// secret-adjacent text is folded into an error or log message.
//
// Over-redaction is acceptable here: unlike the server's audit path there is no
// verification that depends on the exact text, so the patterns cast a wide net.
package redact

import "regexp"

// Redacted is the placeholder substituted for a matched secret.
const Redacted = "[redacted]"

var (
	// "Authorization: Bearer <token>" and bare "Bearer <token>".
	bearer = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9._~+/=-]+`)

	// A PEM private-key block (Ed25519 signing/backup key material).
	pemPrivateKey = regexp.MustCompile(
		`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// A JWT: three base64url segments separated by dots.
	jwt = regexp.MustCompile(`[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`)

	// key=value / key: value where the key contains a sensitive part. Covers
	// enrollment_token, agent_token, server-side "detail":"...secret..." forms.
	kvSecret = regexp.MustCompile(
		`(?i)([\w.-]*(?:password|passphrase|secret|token|authorization|bearer|` +
			`credential|private_key|privatekey|api_key|apikey|session_key|cookie)` +
			`[\w.-]*)["']?\s*[:=]\s*["']?[^\s"',;}&]+`)
)

// Text returns s with credential-shaped substrings replaced by Redacted.
func Text(s string) string {
	if s == "" {
		return s
	}
	s = pemPrivateKey.ReplaceAllString(s, Redacted)
	s = bearer.ReplaceAllString(s, "Bearer "+Redacted)
	s = jwt.ReplaceAllString(s, Redacted)
	s = kvSecret.ReplaceAllString(s, "$1="+Redacted)
	return s
}
