package manned

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// slowWriter is a ts.Writer whose calls wait for release (a slow
// JetStream), recording the gaps.
type slowWriter struct {
	release chan struct{}
	mu      sync.Mutex
	calls   int
	gaps    []ts.GapMessage
}

func (w *slowWriter) Enqueue(context.Context, string, any, string) error {
	w.mu.Lock()
	w.calls++
	w.mu.Unlock()
	<-w.release
	return nil
}

func (w *slowWriter) EnqueueGap(_ context.Context, g ts.GapMessage, _ string) error {
	w.mu.Lock()
	w.calls++
	w.mu.Unlock()
	<-w.release
	w.mu.Lock()
	w.gaps = append(w.gaps, g)
	w.mu.Unlock()
	return nil
}

// Audit B-S7, E-10: with JetStream slow and the queue full, Rows (called
// from the WebSocket reader and the status loop) sheds without calling
// JetStream, and the drain worker records the shed rows as one
// coalesced gap, every row counted.
func TestShedRowsNeverBlockTheReader(t *testing.T) {
	w := &slowWriter{release: make(chan struct{})}
	cnt := &core.Counters{}
	s := &BusSink{Writer: w, Counters: cnt, QueueSize: 2}
	s.init()
	s.Rows([]Row{{}})
	s.Rows([]Row{{}})
	done := make(chan struct{})
	go func() {
		for range 3 {
			s.Rows([]Row{{}, {}})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(w.release)
		t.Fatal("Rows blocked on a slow JetStream while shedding")
	}
	w.mu.Lock()
	calls := w.calls
	w.mu.Unlock()
	if calls != 0 || cnt.Get(CounterRowsShed) != 6 {
		t.Fatalf("JetStream called from Rows: %d calls, counters %v", calls, cnt.Snapshot())
	}
	close(w.release)
	s.flushShed(context.Background())
	if len(w.gaps) != 1 || w.gaps[0].Count != 6 || w.gaps[0].Cause != CauseHandOver {
		t.Fatalf("gaps %+v", w.gaps)
	}
	s.flushShed(context.Background())
	if len(w.gaps) != 1 {
		t.Fatal("a flush with nothing shed recorded a gap")
	}
}
