// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

func spkiPin(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256/" + base64.StdEncoding.EncodeToString(digest[:])
}

func trustedTLSConfig(cert *x509.Certificate) *tls.Config {
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{RootCAs: roots}
}

func getWithPins(t *testing.T, server *httptest.Server, pins []string, tlsConfig *tls.Config) error {
	t.Helper()
	client, err := newWithTLSConfig(server.URL, "", pins, tlsConfig)
	if err != nil {
		return err
	}
	response, err := client.http.Get(server.URL)
	if err == nil {
		response.Body.Close()
	}
	return err
}

func TestTLSSPKIPinMatchingPinSucceeds(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	cert := server.Certificate()
	if err := getWithPins(t, server, []string{spkiPin(cert)}, trustedTLSConfig(cert)); err != nil {
		t.Fatalf("matching pin failed: %v", err)
	}
}

func TestSPKIPinSurvivesCertificateReissueWithSameKey(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: "reissued.example"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:     []string{"reissued.example"},
		}
		der, createErr := x509.CreateCertificate(
			rand.Reader,
			template,
			template,
			publicKey,
			privateKey,
		)
		if createErr != nil {
			t.Fatal(createErr)
		}
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		return cert
	}
	first := issue(1)
	second := issue(2)
	if string(first.Raw) == string(second.Raw) {
		t.Fatal("test certificates unexpectedly identical")
	}
	if spkiPin(first) != spkiPin(second) {
		t.Fatal("same public key produced different SPKI pins after reissue")
	}
}

func TestTLSSPKIPinMismatchFailsClosed(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	wrongDigest := sha256.Sum256([]byte("not the server SPKI"))
	wrongPin := "sha256/" + base64.StdEncoding.EncodeToString(wrongDigest[:])
	err := getWithPins(t, server, []string{wrongPin}, trustedTLSConfig(server.Certificate()))
	if err == nil || !strings.Contains(err.Error(), "SPKI pin mismatch") {
		t.Fatalf("wrong pin error = %v, want fail-closed pin mismatch", err)
	}
}

func TestTLSSPKIPinOverlapAcceptsEitherPin(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	oldDigest := sha256.Sum256([]byte("old key"))
	oldPin := "sha256/" + base64.StdEncoding.EncodeToString(oldDigest[:])
	pins := []string{oldPin, spkiPin(server.Certificate())}
	if err := getWithPins(t, server, pins, trustedTLSConfig(server.Certificate())); err != nil {
		t.Fatalf("overlap pins rejected current server key: %v", err)
	}
}

func TestEmptyTLSSPKIPinsUseNormalTLSValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	if err := getWithPins(t, server, nil, trustedTLSConfig(server.Certificate())); err != nil {
		t.Fatalf("empty pins changed trusted TLS behavior: %v", err)
	}
	if err := getWithPins(t, server, nil, &tls.Config{}); err == nil {
		t.Fatal("empty pins bypassed normal trust-chain validation")
	}
}

func TestMatchingPinDoesNotBypassNormalTLSValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := getWithPins(t, server, []string{spkiPin(server.Certificate())}, &tls.Config{})
	if err == nil {
		t.Fatal("matching pin bypassed untrusted certificate rejection")
	}
	if strings.Contains(err.Error(), "SPKI pin mismatch") {
		t.Fatalf("pin check ran instead of normal PKI rejection: %v", err)
	}
}

func TestMatchingPinDoesNotBypassHostnameValidation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	tlsConfig := trustedTLSConfig(server.Certificate())
	tlsConfig.ServerName = "wrong-host.example"
	err := getWithPins(t, server, []string{spkiPin(server.Certificate())}, tlsConfig)
	if err == nil {
		t.Fatal("matching pin bypassed hostname validation")
	}
	if strings.Contains(err.Error(), "SPKI pin mismatch") {
		t.Fatalf("pin check ran instead of hostname rejection: %v", err)
	}
}

func TestExpiredPinnedCertificateStillFails(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired test certificate"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  privateKey,
	}}}
	server.StartTLS()
	defer server.Close()

	err = getWithPins(t, server, []string{spkiPin(cert)}, trustedTLSConfig(cert))
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired pinned certificate error = %v, want expiry rejection", err)
	}
}

func TestTLSSPKIPinConfigurationIsStrict(t *testing.T) {
	for _, pins := range [][]string{
		{"not-prefixed"},
		{"sha256/not-base64"},
		{"sha256/" + base64.StdEncoding.EncodeToString([]byte("too short"))},
	} {
		if _, err := NewWithTLSSPKIPins("https://rmm.example", "", pins); err == nil {
			t.Fatalf("invalid pins accepted: %v", pins)
		}
	}
	digest := sha256.Sum256([]byte("valid pin"))
	validPin := "sha256/" + base64.StdEncoding.EncodeToString(digest[:])
	if _, err := NewWithTLSSPKIPins("http://rmm.example", "", []string{validPin}); err == nil {
		t.Fatal("pinning accepted a non-HTTPS server URL")
	}
}

func TestHeartbeatStopsWhenContextIsCancelled(t *testing.T) {
	requestStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-releaseHandler
	}))
	defer func() {
		close(releaseHandler)
		server.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := New(server.URL, "test-token").Heartbeat(ctx, telemetry.Sample{}, nil)
		result <- err
	}()

	select {
	case <-requestStarted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("heartbeat request did not reach test server")
	}

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Heartbeat error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Heartbeat did not return after context cancellation")
	}
}
