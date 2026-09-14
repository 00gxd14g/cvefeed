package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestADeterminateBarShowsWhatIsDoneAndWhatIsLeft(t *testing.T) {
	var buf bytes.Buffer
	b := newFor(&buf, true)
	b.Stage("probing")
	b.Total(100)
	b.At(25, time.Now().Add(-10*time.Second))
	b.render()

	out := buf.String()
	for _, want := range []string{"probing", "25%", "25/100"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q does not contain %q", out, want)
		}
	}
	// A quarter done in ten seconds is thirty more; the estimate does not have
	// to be exact, but it has to be there and be a time.
	if !strings.Contains(out, "s left") && !strings.Contains(out, "m left") {
		t.Errorf("output %q carries no estimate", out)
	}
}

// A single opaque subprocess gives no way to know how far along it is, and
// inventing a percentage for it would be a lie that reads exactly like a
// measurement.
func TestAnIndeterminateBarShowsElapsedAndNoPercentage(t *testing.T) {
	var buf bytes.Buffer
	b := newFor(&buf, true)
	b.Stage("identifying with nmap")
	b.At(0, time.Now().Add(-3*time.Second))
	b.render()

	out := buf.String()
	if strings.Contains(out, "%") {
		t.Errorf("output %q claims a percentage for work it cannot measure", out)
	}
	if !strings.Contains(out, "identifying with nmap") {
		t.Errorf("output %q does not name the stage", out)
	}
	if !strings.Contains(out, "3s") {
		t.Errorf("output %q does not show elapsed time", out)
	}
}

// Redirected to a file or a pipe, the bar must write nothing at all: control
// codes in a log are worse than no progress.
func TestNothingIsWrittenWhenTheOutputIsNotATerminal(t *testing.T) {
	var buf bytes.Buffer
	b := newFor(&buf, false)
	b.Stage("probing")
	b.Total(10)
	b.At(5, time.Now())
	b.render()
	b.Done()
	if buf.Len() != 0 {
		t.Fatalf("wrote %q to a non-terminal", buf.String())
	}
}

func TestDoneClearsTheLine(t *testing.T) {
	var buf bytes.Buffer
	b := newFor(&buf, true)
	b.Stage("probing")
	b.Total(10)
	b.At(10, time.Now())
	b.render()
	buf.Reset()
	b.Done()
	if !strings.Contains(buf.String(), "\r") {
		t.Error("Done did not return to the start of the line")
	}
}

func TestHumanDuration(t *testing.T) {
	cases := map[time.Duration]string{
		900 * time.Millisecond: "1s",
		45 * time.Second:       "45s",
		90 * time.Second:       "1m30s",
		3700 * time.Second:     "1h1m",
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

// Done cleared the line and returned while the ticker goroutine could still
// fire once more, which drew the bar back over the report that followed. Done
// has to outlive the ticker, and nothing may draw once it has run.
func TestNothingIsDrawnAfterDone(t *testing.T) {
	var buf lockedBuffer
	b := newFor(&buf, true)
	b.Stage("sweeping")
	b.Tick(time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	b.Done()
	clearSeq := "\r\033[2K"
	if !strings.HasSuffix(buf.String(), clearSeq) {
		t.Fatalf("output does not end with the clear sequence: %q", buf.String())
	}
	n := buf.Len()
	// A late tick would land in this window. render must refuse it.
	time.Sleep(20 * time.Millisecond)
	b.Render()
	b.render()
	if buf.Len() != n {
		t.Fatalf("%q was written after Done", buf.String()[n:])
	}
	// A second Done is a no-op rather than a second clear or a closed-channel panic.
	b.Done()
	if buf.Len() != n {
		t.Fatalf("second Done wrote %q", buf.String()[n:])
	}
}

// Tick after Done must not start a goroutine that nobody will ever wait for.
func TestTickAfterDoneStartsNothing(t *testing.T) {
	var buf lockedBuffer
	b := newFor(&buf, true)
	b.Done()
	n := buf.Len()
	b.Tick(time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	if buf.Len() != n {
		t.Fatalf("%q was drawn by a ticker started after Done", buf.String()[n:])
	}
}

// lockedBuffer lets the test read what the bar wrote while the ticker
// goroutine may still be writing. The race detector would otherwise report
// the test's own read rather than the bug under test.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *lockedBuffer) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Len()
}
