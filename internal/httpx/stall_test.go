package httpx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A connection that goes silent part-way through the body is not a hypothetical:
// an OSV full-export download stalled at 1.55 GiB and held a backfill
// indefinitely, because nothing in the client bounds the body read.
// http.Client.Timeout is an end-to-end deadline that would abort a legitimately
// long transfer, and ResponseHeaderTimeout stops covering the exchange the
// moment the headers arrive.
func TestBodyThatStopsMakingProgressFailsInsteadOfHanging(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1024")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("the first bytes arrive"))
		w.(http.Flusher).Flush()
		// ...and then the server says nothing more, without closing.
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := NewClient(ClientOptions{Timeout: 2 * time.Second, IdleTimeout: 300 * time.Millisecond})
	defer c.Close()

	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v; the headers and first bytes did arrive", err)
	}
	defer resp.Body.Close()

	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(resp.Body)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("the read returned success although the body was never finished")
		}
		if !errors.Is(err, ErrStalled) {
			t.Fatalf("err = %v, want ErrStalled so a caller can tell a dead connection from a refusal", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the read hung; a silent connection blocks the collector forever")
	}
}

// The guard must not cut a transfer that is merely slow, which is the failure
// mode the end-to-end deadline had and the reason it was removed.
func TestASlowBodyIsNotMistakenForAStalledOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 8; i++ {
			w.Write([]byte("chunk"))
			w.(http.Flusher).Flush()
			time.Sleep(120 * time.Millisecond)
		}
	}))
	defer srv.Close()

	// Total transfer ~1s, far beyond the idle window, but never idle for it.
	c := NewClient(ClientOptions{Timeout: 2 * time.Second, IdleTimeout: 400 * time.Millisecond})
	defer c.Close()

	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read error = %v; a slow transfer must run as long as it needs", err)
	}
	if len(b) != 40 {
		t.Fatalf("read %d bytes, want the whole 40", len(b))
	}
}

// The guard must measure the connection's silence, not the caller's. A consumer
// that takes its time between reads — writing each chunk to a slow disk, or
// blocked on a full queue downstream — leaves the body idle for as long as it
// likes, and cutting that transfer would punish backpressure as if it were a
// dead socket.
func TestASlowConsumerDoesNotTripTheGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for i := 0; i < 6; i++ {
			w.Write([]byte("chunk"))
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()

	c := NewClient(ClientOptions{Timeout: 2 * time.Second, IdleTimeout: 200 * time.Millisecond})
	defer c.Close()

	resp, err := c.Fetch(context.Background(), Request{URL: srv.URL})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	defer resp.Body.Close()

	var total int
	buf := make([]byte, 5)
	for {
		// The server has everything ready; this reader is the slow part.
		time.Sleep(300 * time.Millisecond)
		n, err := resp.Body.Read(buf)
		total += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read error = %v after %d bytes; the socket was never silent, the reader was",
				err, total)
		}
	}
	if total != 30 {
		t.Fatalf("read %d bytes, want 30", total)
	}
}
