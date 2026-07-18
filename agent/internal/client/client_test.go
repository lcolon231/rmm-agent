package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcolon231/rmm/agent/internal/telemetry"
)

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
