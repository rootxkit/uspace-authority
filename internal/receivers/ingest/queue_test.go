package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

type fakeMsg struct {
	data    []byte
	meta    *jetstream.MsgMetadata
	metaErr error
	acked   int
	naked   int
	termed  int
}

func (m *fakeMsg) Data() []byte                              { return m.data }
func (m *fakeMsg) Metadata() (*jetstream.MsgMetadata, error) { return m.meta, m.metaErr }
func (m *fakeMsg) Ack() error                                { m.acked++; return nil }
func (m *fakeMsg) NakWithDelay(time.Duration) error          { m.naked++; return nil }
func (m *fakeMsg) Term() error                               { m.termed++; return nil }

type fakeStore struct {
	mu      sync.Mutex
	rows    []*ridpipe.Batch
	gaps    []Gap
	rowsErr error
	gapsErr error
}

func (s *fakeStore) PutRows(_ context.Context, b *ridpipe.Batch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rowsErr != nil {
		return s.rowsErr
	}
	s.rows = append(s.rows, b)
	return nil
}

func (s *fakeStore) PutGap(_ context.Context, g Gap) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gapsErr != nil {
		return s.gapsErr
	}
	s.gaps = append(s.gaps, g)
	return nil
}

type countingSink struct {
	seen  map[string]int
	err   error
	panic bool
}

func (s *countingSink) Observe(_ context.Context, b *ridpipe.Batch) error {
	if s.seen == nil {
		s.seen = map[string]int{}
	}
	s.seen[b.ID]++
	if s.panic {
		panic("decoder bug")
	}
	return s.err
}

func queued(t *testing.T, id string, rows int, seq, pending uint64, at time.Time) *fakeMsg {
	t.Helper()
	b := ridpipe.Batch{ID: id, ReceiverID: "rx-1", Cell3: "c3:131:224", Rows: make([]ridpipe.Row, rows)}
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeMsg{data: data, meta: &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: seq}, NumPending: pending, Timestamp: at}}
}

func newWorker(sink ridpipe.Sink, store RowStore, now time.Time) *Worker {
	return &Worker{
		Sink: sink, Store: store, Config: QueueConfig{MaxBatches: 10, MaxAge: 10 * time.Minute, MaxAckPending: 4},
		Counters: &core.Counters{}, Limiter: quietLimiter(), Now: func() time.Time { return now }, Retry: time.Millisecond,
	}
}

// The success path: decoded once, rows handed over, acknowledged, counted.
func TestWorkerHandsRowsOverThenAcks(t *testing.T) {
	now := time.Unix(10_000, 0)
	sink, store := &countingSink{}, &fakeStore{}
	w := newWorker(sink, store, now)
	stored := 0
	w.OnStored = func(_ string, n int) { stored += n }
	m := queued(t, "rx-1:a", 3, 1, 0, now)
	w.Handle(context.Background(), m)
	if m.acked != 1 || len(store.rows) != 1 || sink.seen["rx-1:a"] != 1 || stored != 3 ||
		w.Counters.Get(CounterRowsStored) != 3 || w.Counters.Get(CounterBatchesStored) != 1 {
		t.Fatalf("acked %d stored %d counters %v", m.acked, len(store.rows), w.Counters.Snapshot())
	}
}

// SC-18 (worker side): with storage down the batch waits in the queue
// (nak, no ack) and is not decoded twice; when storage returns it is
// handed over once and acknowledged.
func TestWorkerKeepsTheBatchQueuedWhileStorageIsDown(t *testing.T) {
	now := time.Unix(10_000, 0)
	sink, store := &countingSink{}, &fakeStore{rowsErr: errors.New("TSW unavailable")}
	w := newWorker(sink, store, now)
	m := queued(t, "rx-1:a", 2, 1, 0, now)
	for range 3 {
		w.Handle(context.Background(), m)
	}
	if m.naked != 3 || m.acked != 0 || w.Counters.Get(CounterStorageUnavailable) != 3 {
		t.Fatalf("down: naked %d acked %d", m.naked, m.acked)
	}
	store.rowsErr = nil
	w.Handle(context.Background(), m)
	if m.acked != 1 || len(store.rows) != 1 || sink.seen["rx-1:a"] != 1 {
		t.Fatalf("back: acked %d rows %d decoded %d times", m.acked, len(store.rows), sink.seen["rx-1:a"])
	}
}

// 05 §5, E-10 (SC-18 step 3): past the queue's bound the oldest batch is
// shed with a gap record and counted, never silently; the gap record
// waits while storage is down and is written when it returns. A batch
// within the bound beside it is stored (E-01).
func TestWorkerShedsTheOldestPastTheBoundWithAGapRecord(t *testing.T) {
	now := time.Unix(10_000, 0)
	store := &fakeStore{gapsErr: errors.New("TSW unavailable")}
	w := newWorker(&countingSink{}, store, now)
	shed := 0
	w.OnShed = func(_ string, n int) { shed += n }
	old := queued(t, "rx-1:old", 4, 7, 10, now) // 10 batches behind it: at the bound
	w.Handle(context.Background(), old)
	if old.termed != 1 || old.acked != 0 || w.Counters.Get(CounterShedFull) != 1 || w.Counters.Get(CounterShedObservations) != 4 || shed != 4 {
		t.Fatalf("shed: %+v %v", old, w.Counters.Snapshot())
	}
	if w.PendingGaps() != 1 || len(store.gaps) != 0 {
		t.Fatalf("gap pending %d written %d", w.PendingGaps(), len(store.gaps))
	}
	aged := queued(t, "rx-1:aged", 1, 8, 0, now.Add(-11*time.Minute))
	w.Handle(context.Background(), aged)
	if aged.termed != 1 || w.Counters.Get(CounterShedAge) != 1 {
		t.Fatalf("age: %+v", aged)
	}
	store.gapsErr = nil
	within := queued(t, "rx-1:new", 1, 9, 9, now)
	w.Handle(context.Background(), within)
	if within.acked != 1 || len(store.gaps) != 2 || w.PendingGaps() != 0 {
		t.Fatalf("within: acked %d gaps %d pending %d", within.acked, len(store.gaps), w.PendingGaps())
	}
	g := store.gaps[0]
	if g.Cause != CauseQueueFull || g.Count != 4 || g.FromSeq != 7 || g.Table != RowsTable || g.ReceiverID != "rx-1" {
		t.Fatalf("gap %+v", g)
	}
	if store.gaps[1].Cause != CauseQueueAge {
		t.Fatalf("gap %+v", store.gaps[1])
	}
}

// E-10: the gap records held while storage is down are bounded; past the
// bound they merge into the last one, so the count of shed observations
// is kept whole.
func TestPendingGapsAreBoundedWithoutLosingTheCount(t *testing.T) {
	w := newWorker(&countingSink{}, &fakeStore{}, time.Unix(1, 0))
	for i := range maxPendingGaps + 10 {
		w.addGap(Gap{Cause: CauseQueueFull, Count: 1, FromSeq: uint64(i), ToSeq: uint64(i)})
	}
	total := 0
	for _, g := range w.pending {
		total += g.Count
	}
	if len(w.pending) != maxPendingGaps || total != maxPendingGaps+10 || w.Counters.Get(CounterGapsDropped) != 10 {
		t.Fatalf("held %d total %d", len(w.pending), total)
	}
	if last := w.pending[len(w.pending)-1]; last.ToSeq != maxPendingGaps+9 {
		t.Fatalf("last %+v", last)
	}
}

// A corrupt queue message is terminated with a gap record; a decoder
// that fails or panics does not stop the raw rows (B-12).
func TestWorkerSurvivesCorruptMessagesAndAFailingDecoder(t *testing.T) {
	now := time.Unix(10_000, 0)
	store := &fakeStore{}
	w := newWorker(&countingSink{err: errors.New("bad frame")}, store, now)
	corrupt := &fakeMsg{data: []byte("{"), meta: &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: 3}}}
	w.Handle(context.Background(), corrupt)
	noMeta := &fakeMsg{data: []byte("{}"), metaErr: errors.New("no metadata")}
	w.Handle(context.Background(), noMeta)
	if corrupt.termed != 1 || noMeta.termed != 1 || w.Counters.Get(CounterQueueCorrupt) != 2 || w.PendingGaps() != 1 {
		t.Fatalf("corrupt: %v", w.Counters.Snapshot())
	}
	m := queued(t, "rx-1:a", 1, 4, 0, now)
	w.Handle(context.Background(), m)
	if m.acked != 1 || w.Counters.Get(CounterSinkFailed) != 1 {
		t.Fatalf("failing sink: %v", w.Counters.Snapshot())
	}
	w.Sink = &countingSink{panic: true}
	p := queued(t, "rx-1:b", 1, 5, 0, now)
	w.Handle(context.Background(), p)
	if p.acked != 1 || w.Counters.Get(CounterSinkPanicked) != 1 || len(store.rows) != 2 {
		t.Fatalf("panicking sink: %v", w.Counters.Snapshot())
	}
}

func TestHardMaxBatchesCoversTheShedBoundAndTheInFlight(t *testing.T) {
	c := QueueConfig{MaxBatches: 100, MaxAckPending: 10}
	if c.HardMaxBatches() != 220 {
		t.Fatal(c.HardMaxBatches())
	}
	if QueueSubject("c3:131:224") != "ingest.v1.c3:131:224" {
		t.Fatal(QueueSubject("c3:131:224"))
	}
}

// Every decoder entry is fuzzed: a queue message of any bytes settles
// (ack, nak or term) without a panic.
func FuzzWorkerHandle(f *testing.F) {
	f.Add([]byte(`{"id":"rx-1:a","receiver_id":"rx-1","rows":[{"payload":"AQ=="}]}`), uint64(0))
	f.Add([]byte(`{`), uint64(5))
	f.Add([]byte(`{"id":""}`), uint64(100))
	f.Fuzz(func(t *testing.T, data []byte, pending uint64) {
		w := newWorker(&countingSink{}, &fakeStore{}, time.Unix(10_000, 0))
		m := &fakeMsg{data: data, meta: &jetstream.MsgMetadata{NumPending: pending, Timestamp: time.Unix(10_000, 0)}}
		w.Handle(context.Background(), m)
		if m.acked+m.naked+m.termed != 1 {
			t.Fatalf("settled %d times", m.acked+m.naked+m.termed)
		}
	})
}
