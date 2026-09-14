package httpx

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ErrStalled reports a response body that stopped delivering data.
//
// It is distinct from a refusal on purpose: a stall says the transfer can be
// retried unchanged, where a 4xx says it cannot.
var ErrStalled = errors.New("httpx: transfer stalled")

// stallGuard fails a response body that stops making progress.
//
// Nothing else bounds a body read. http.Client.Timeout is an end-to-end
// deadline that would abort a legitimately long download — the bulk artefacts
// here run past a gigabyte — and ResponseHeaderTimeout stops covering the
// exchange the moment the headers arrive. Between them sits a gap in which a
// connection that goes silent blocks forever, which is not hypothetical: an OSV
// full-export download stalled at 1.55 GiB and held a backfill indefinitely
// while the process looked healthy.
//
// The window covers only the time spent blocked inside the underlying Read, and
// is armed and disarmed around each one. That is what separates the two ways a
// transfer can look idle: a socket delivering nothing trips it, while a consumer
// that takes its time between reads — writing to a slow disk, or blocked on a
// full queue downstream — never does, because the clock is not running while
// the caller is away. A guard that measured wall-clock idleness instead would
// punish backpressure as if it were a dead connection.
//
// The timer closes the underlying body, which is what unblocks a Read already
// waiting on the socket; a flag distinguishes that close from an ordinary end of
// stream, so the error names the cause instead of surfacing as a bare "use of
// closed connection".
type stallGuard struct {
	rc   io.ReadCloser
	idle time.Duration

	mu      sync.Mutex
	timer   *time.Timer
	stalled bool
	closed  bool
}

func newStallGuard(rc io.ReadCloser, idle time.Duration) io.ReadCloser {
	if idle <= 0 {
		return rc
	}
	g := &stallGuard{rc: rc, idle: idle}
	// Created stopped: the clock starts when a read blocks, not when the body
	// is handed to the caller.
	g.timer = time.AfterFunc(idle, g.trip)
	g.timer.Stop()
	return g
}

// trip is the timer's callback: mark the transfer dead and close the body under
// the blocked reader.
func (g *stallGuard) trip() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.stalled = true
	g.mu.Unlock()
	g.rc.Close()
}

func (g *stallGuard) Read(p []byte) (int, error) {
	g.mu.Lock()
	// A timer that has already tripped must not be re-armed; the transfer is
	// being torn down.
	arm := !g.stalled && !g.closed
	if arm {
		g.timer.Reset(g.idle)
	}
	g.mu.Unlock()

	n, err := g.rc.Read(p)

	if arm {
		g.mu.Lock()
		g.timer.Stop()
		g.mu.Unlock()
	}
	if err != nil && err != io.EOF {
		g.mu.Lock()
		stalled := g.stalled
		g.mu.Unlock()
		if stalled {
			return n, fmt.Errorf("%w: no data for %s", ErrStalled, g.idle)
		}
	}
	return n, err
}

func (g *stallGuard) Close() error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	g.timer.Stop()
	g.mu.Unlock()
	return g.rc.Close()
}
