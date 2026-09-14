// Package progress reports how a long operation is going, on a terminal only.
//
// A scan of a subnet takes minutes and until now printed nothing at all until
// it finished, which is indistinguishable from being hung. The rule this
// follows is that it never claims to know more than it does: work that can be
// counted gets a bar and an estimate, and work that is one opaque subprocess
// gets its name and the time it has been running. Inventing a percentage for
// the second case would read exactly like a measurement of the first.
package progress

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Bar renders a single updating line.
//
// It is safe to call from several goroutines, because the things it measures —
// hosts, ports, subprocesses — are examined concurrently.
type Bar struct {
	w       io.Writer
	tty     bool
	mu      sync.Mutex
	stage   string
	total   int
	done    int
	started time.Time
	last    time.Time
	width   int
	stop    chan struct{}
	stopped bool
	// ticker counts the goroutine Tick starts, so that Done can wait for it.
	// Without the wait, Done cleared the line and returned while the ticker
	// was still able to fire once more and draw the bar back over the report
	// that followed.
	ticker sync.WaitGroup
}

// New builds a Bar on stderr, which is where progress belongs: stdout carries
// the report, and a caller piping it into a file must not receive control codes
// in the middle of it.
func New() *Bar { return newFor(os.Stderr, isTerminal(os.Stderr)) }

func newFor(w io.Writer, tty bool) *Bar {
	return &Bar{w: w, tty: tty, started: time.Now(), width: 24, stop: make(chan struct{})}
}

// Stage names what is happening now. Setting it restarts the clock, because the
// elapsed time a reader cares about is the current step's rather than the
// whole run's.
func (b *Bar) Stage(name string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.stage, b.started, b.done, b.total = name, time.Now(), 0, 0
	b.mu.Unlock()
	b.Render()
}

// Total declares how many units this stage has, which is what turns the bar
// determinate. Leaving it zero says the work cannot be counted.
func (b *Bar) Total(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.total = n
	b.mu.Unlock()
}

// Add records completed units.
func (b *Bar) Add(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.done += n
	b.mu.Unlock()
	b.Render()
}

// At sets the count directly, with the moment the stage began. Used by tests and
// by stages that learn their position rather than counting up to it — masscan
// reports a percentage rather than a tally.
func (b *Bar) At(done int, since time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.done, b.started = done, since
	b.mu.Unlock()
}

// Set records an absolute position, for a stage that learns where it is rather
// than counting up to it — masscan reports a percentage and no tally.
func (b *Bar) Set(n int) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.done = n
	b.mu.Unlock()
	b.Render()
}

// Tick starts a goroutine that redraws while nothing else is happening, so an
// indeterminate stage still shows time passing. Stop it with Done.
func (b *Bar) Tick(every time.Duration) {
	if b == nil || !b.tty {
		return
	}
	// The goroutine is registered under the lock so that it is serialised
	// with Done: a Tick after Done starts nothing, and a Tick before it is
	// always counted before Done waits.
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.ticker.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.ticker.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				b.Render()
			case <-b.stop:
				return
			}
		}
	}()
}

// Render draws the line, at most a few times a second.
func (b *Bar) Render() {
	if b == nil || !b.tty {
		return
	}
	b.mu.Lock()
	if time.Since(b.last) < 100*time.Millisecond {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	b.render()
}

func (b *Bar) render() {
	if b == nil || !b.tty {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		// Done has cleared the line, or is about to under this same lock.
		// Drawing now would put the bar back over the report.
		return
	}
	b.last = time.Now()

	elapsed := time.Since(b.started)
	var line string
	if b.total > 0 {
		frac := float64(b.done) / float64(b.total)
		if frac > 1 {
			frac = 1
		}
		filled := int(frac * float64(b.width))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", b.width-filled)
		line = fmt.Sprintf("  %s  %s  %3.0f%%  %d/%d", b.stage, bar, frac*100, b.done, b.total)
		if eta, ok := estimate(b.done, b.total, elapsed); ok {
			line += "  " + humanDuration(eta) + " left"
		}
	} else {
		line = fmt.Sprintf("  %s %s  %s", spinner(elapsed), b.stage, humanDuration(elapsed))
	}
	fmt.Fprintf(b.w, "\r\033[2K%s", line)
}

// Done clears the line so the report that follows starts on clean ground.
//
// It returns only once the ticker goroutine has exited, and the clear is
// written under the same lock that render draws under, so nothing can be
// drawn after it. Calling it twice is harmless: the second call finds the bar
// stopped and does nothing.
func (b *Bar) Done() {
	if b == nil {
		return
	}
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	close(b.stop)
	b.mu.Unlock()

	b.ticker.Wait()

	if !b.tty {
		return
	}
	b.mu.Lock()
	fmt.Fprint(b.w, "\r\033[2K")
	b.mu.Unlock()
}

// estimate projects the remaining time from the rate observed so far.
//
// It refuses to answer until enough has happened to mean anything: a projection
// from two samples in the first half-second is noise presented as knowledge.
func estimate(done, total int, elapsed time.Duration) (time.Duration, bool) {
	if done <= 0 || done >= total || elapsed < time.Second {
		return 0, false
	}
	per := elapsed / time.Duration(done)
	return per * time.Duration(total-done), true
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func spinner(elapsed time.Duration) string {
	return spinnerFrames[int(elapsed/(100*time.Millisecond))%len(spinnerFrames)]
}

// humanDuration renders a duration the way someone waiting on it would say it.
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
}
