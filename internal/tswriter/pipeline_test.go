package tswriter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// fakeMsg is a delivered TSW message.
type fakeMsg struct {
	data   []byte
	hdr    nats.Header
	seq    uint64
	noMeta bool

	mu         sync.Mutex
	acks, naks int
	inProgress int
}

func (m *fakeMsg) Data() []byte         { return m.data }
func (m *fakeMsg) Headers() nats.Header { return m.hdr }
func (m *fakeMsg) Metadata() (*jetstream.MsgMetadata, error) {
	if m.noMeta {
		return nil, errors.New("not a JetStream message")
	}
	return &jetstream.MsgMetadata{Sequence: jetstream.SequencePair{Stream: m.seq}}, nil
}

func (m *fakeMsg) Ack() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.acks++
	return nil
}

func (m *fakeMsg) Nak() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.naks++
	return nil
}

func (m *fakeMsg) InProgress() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inProgress++
	return nil
}

func (m *fakeMsg) counts() (acks, naks, inProgress int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.acks, m.naks, m.inProgress
}

// fakeSource delivers its pending messages in order.
type fakeSource struct {
	mu       sync.Mutex
	pending  []Msg
	fetches  int
	floor    uint64
	holes    func([]Jump) ([]Hole, error)
	jumps    []Jump
	fetchErr error
	// last and numPending are the stream's last sequence and this
	// consumer's undelivered count (Cursor).
	last, numPending uint64
}

func (s *fakeSource) add(ms ...Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, ms...)
}

func (s *fakeSource) Fetch(ctx context.Context, n int, wait time.Duration) ([]Msg, error) {
	s.mu.Lock()
	s.fetches++
	if s.fetchErr != nil {
		err := s.fetchErr
		s.mu.Unlock()
		return nil, err
	}
	k := min(n, len(s.pending))
	out := append([]Msg(nil), s.pending[:k]...)
	s.pending = s.pending[k:]
	s.mu.Unlock()
	if k == 0 {
		sleep(ctx, min(wait, 5*time.Millisecond))
	}
	return out, nil
}

func (s *fakeSource) AckFloor(context.Context) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.floor, nil
}

// setLast sets the stream's last sequence and what is pending for this
// consumer (Cursor).
func (s *fakeSource) setLast(last, pending uint64) {
	s.mu.Lock()
	s.last, s.numPending = last, pending
	s.mu.Unlock()
}

// Cursor reads the stream's last sequence, then the consumer's floor and
// pending count.
func (s *fakeSource) Cursor(context.Context) (Cursor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Cursor{StreamLast: s.last, AckFloor: s.floor, NumPending: s.numPending}, nil
}

// setFloor moves the consumer's ack floor, as a purge does.
func (s *fakeSource) setFloor(f uint64) {
	s.mu.Lock()
	s.floor = f
	s.mu.Unlock()
}

func (s *fakeSource) Holes(_ context.Context, jumps []Jump) ([]Hole, error) {
	s.mu.Lock()
	s.jumps = append(s.jumps, jumps...)
	h := s.holes
	s.mu.Unlock()
	if h == nil {
		return make([]Hole, len(jumps)), nil
	}
	return h(jumps)
}

func (s *fakeSource) fetchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func (s *fakeSource) pendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// fakeStore records every committed write; fail decides a failure.
type fakeStore struct {
	mu      sync.Mutex
	fail    func(parts []ts.Part) error
	commits [][]ts.Part
	calls   int
	dupes   map[string]bool
	// preset is a position stored before the test (presetKnown), posErr
	// a position that cannot be read.
	preset      uint64
	presetKnown bool
	posErr      error
}

func (s *fakeStore) Write(_ context.Context, parts ...ts.Part) ([]ts.Written, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		if err := s.fail(parts); err != nil {
			return nil, err
		}
	}
	if s.dupes == nil {
		s.dupes = map[string]bool{}
	}
	out := make([]ts.Written, len(parts))
	for i, p := range parts {
		for _, r := range p.Rows {
			k := p.Table.Name + fmt.Sprint(r[0], r[1])
			if s.dupes[k] {
				out[i].Duplicates++
				continue
			}
			s.dupes[k] = true
			out[i].Inserted++
		}
	}
	s.commits = append(s.commits, parts)
	return out, nil
}

// Position is the highest writer_positions row committed for table,
// or what preset says before any.
func (s *fakeStore) Position(_ context.Context, table, _ string) (uint64, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.posErr != nil {
		return 0, false, s.posErr
	}
	seq, known := s.preset, s.presetKnown
	for _, c := range s.commits {
		for _, p := range c {
			if p.Table.Name != ts.WriterPositions.Name {
				continue
			}
			for _, r := range p.Rows {
				if r[0] == table {
					seq, known = max(seq, uint64(r[2].(int64))), true
				}
			}
		}
	}
	return seq, known, nil
}

func (s *fakeStore) setFail(f func([]ts.Part) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = f
}

// rows returns every committed row of table.
func (s *fakeStore) rows(table string) [][]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]any
	for _, c := range s.commits {
		for _, p := range c {
			if p.Table.Name == table {
				out = append(out, p.Rows...)
			}
		}
	}
	return out
}

func (s *fakeStore) gaps() []map[string]any {
	var out []map[string]any
	for _, r := range s.rows(ts.WriterGaps.Name) {
		m := map[string]any{}
		for i, c := range ts.WriterGaps.Columns {
			m[c.Name] = r[i]
		}
		out = append(out, m)
	}
	return out
}

// clock runs with real time from t, and advance jumps it forward.
type clock struct {
	mu    sync.Mutex
	t     time.Time
	start time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t.Add(time.Since(c.start))
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// probeTable is a two-column table for the pipeline tests.
var probeTable = ts.Table{Name: "probe", Columns: []ts.Column{{Name: "id", Kind: ts.KindText}, {Name: "at", Kind: ts.KindTime}}}

func rowsMsg(t *testing.T, seq uint64, ids ...string) *fakeMsg {
	t.Helper()
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, map[string]any{"id": id, "at": "2026-10-02T10:00:00Z"})
	}
	b, err := json.Marshal(ts.RowsMessage{Table: probeTable.Name, Rows: rows})
	if err != nil {
		t.Fatal(err)
	}
	return &fakeMsg{data: b, seq: seq}
}

type kit struct {
	p     *Pipeline
	src   *fakeSource
	store *fakeStore
	clk   *clock
	logs  *syncBuf
	c     *core.Counters
}

func newKit(t *testing.T, mutate func(*Config)) *kit {
	t.Helper()
	cfg := Config{
		BatchMaxRows: 1000, BatchMaxWait: 20 * time.Millisecond, QueueMaxRows: 1000, QueueMaxAge: 10 * time.Second,
		FetchMax: 4, FetchWait: 5 * time.Millisecond, WriteTimeout: time.Second, RetryMin: 5 * time.Millisecond,
		RetryMax: 10 * time.Millisecond, AckWait: 60 * time.Second,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	logs := &syncBuf{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	k := &kit{src: &fakeSource{}, store: &fakeStore{}, clk: &clock{t: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC), start: time.Now()}, logs: logs, c: &core.Counters{}}
	k.p = &Pipeline{
		Table: probeTable, Decode: RowsDecoder(probeTable), Source: k.src, Store: k.store, Config: cfg, Counters: k.c,
		Logger: logger, Limiter: logging.NewLimiter(logger, time.Hour, 0, nil), Now: k.clk.now,
	}
	return k
}

func (k *kit) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); k.p.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestBatchIsWrittenThenAcknowledged(t *testing.T) {
	k := newKit(t, nil)
	m1, m2 := rowsMsg(t, 1, "a", "b"), rowsMsg(t, 2, "c")
	k.src.add(m1, m2)
	k.run(t)
	eventually(t, "two acks", func() bool { a1, _, _ := m1.counts(); a2, _, _ := m2.counts(); return a1 == 1 && a2 == 1 })
	if got := len(k.store.rows(probeTable.Name)); got != 3 {
		t.Fatalf("rows %d", got)
	}
	snap := k.c.Snapshot()
	if snap[CounterRowsWritten] != 3 || snap[CounterBatches] == 0 || snap[CounterGaps] != 0 {
		t.Fatalf("counters %v", snap)
	}
	if s := k.p.Snapshot(); s.State != StateOK || s.QueueRows != 0 || s.LastSeq != 2 {
		t.Fatalf("snapshot %+v", s)
	}
}

// E-01 pair of the above: while the store fails nothing is acknowledged,
// the batch is retried, and it is acknowledged once the store is back.
func TestNothingIsAcknowledgedWhileTheWriteFails(t *testing.T) {
	k := newKit(t, nil)
	k.store.setFail(func([]ts.Part) error { return errors.New("connection refused") })
	m := rowsMsg(t, 1, "a")
	k.src.add(m)
	k.run(t)
	eventually(t, "failed writes", func() bool { return k.c.Snapshot()[CounterWriteFailed] >= 3 })
	if a, _, _ := m.counts(); a != 0 {
		t.Fatal("acknowledged before a commit")
	}
	if s := k.p.Snapshot(); s.State != StateWriteFailing || s.QueueRows != 1 {
		t.Fatalf("snapshot %+v", s)
	}
	k.store.setFail(nil)
	eventually(t, "ack after recovery", func() bool { a, _, _ := m.counts(); return a == 1 })
	eventually(t, "state ok", func() bool { return k.p.Snapshot().State == StateOK })
	if !strings.Contains(k.logs.String(), "telemetry writes resumed") {
		t.Fatal("no recovery line")
	}
}

func TestBatchesAreCutAtTheRowBound(t *testing.T) {
	k := newKit(t, func(c *Config) { c.BatchMaxRows = 3; c.BatchMaxWait = time.Hour })
	k.src.add(rowsMsg(t, 1, "a", "b"), rowsMsg(t, 2, "c", "d"), rowsMsg(t, 3, "e"))
	k.run(t)
	eventually(t, "first batch", func() bool { return len(k.store.rows(probeTable.Name)) >= 2 })
	k.store.mu.Lock()
	first := len(k.store.commits[0][0].Rows)
	k.store.mu.Unlock()
	// Whole messages: 2 rows, since the next message would pass 3.
	if first != 2 {
		t.Fatalf("first batch %d rows", first)
	}
}

// B-05: rows already stored are counted as duplicates, not written.
func TestRedeliveredRowsAreCountedAsDuplicates(t *testing.T) {
	k := newKit(t, nil)
	k.src.add(rowsMsg(t, 1, "a"))
	k.run(t)
	eventually(t, "first", func() bool { return k.c.Snapshot()[CounterRowsWritten] == 1 })
	// The same row again (acknowledgement lost, message redelivered).
	k.src.add(rowsMsg(t, 1, "a"))
	eventually(t, "dedupe", func() bool { return k.c.Snapshot()[CounterRowsDeduplicated] == 1 })
	if k.c.Snapshot()[CounterRowsWritten] != 1 {
		t.Fatal("written twice")
	}
}

// E-10: the queue's age bound. With the database down a table holding
// 11 s of rows stops pulling and says spilling; the messages behind wait
// in the stream.
func TestQueueAtTenSecondsOfRowsStopsPulling(t *testing.T) {
	k := newKit(t, nil)
	k.store.setFail(func([]ts.Part) error { return errors.New("database down") })
	k.src.add(rowsMsg(t, 1, "a"))
	k.run(t)
	eventually(t, "queued", func() bool { return k.p.Snapshot().QueueRows == 1 })
	if k.p.Snapshot().State == StateSpilling {
		t.Fatal("spilling under the bound")
	}
	k.clk.advance(11 * time.Second)
	eventually(t, "spilling", func() bool { return k.p.Snapshot().State == StateSpilling })
	k.src.add(rowsMsg(t, 2, "b"))
	before := k.src.fetchCount()
	time.Sleep(100 * time.Millisecond)
	if k.src.fetchCount() != before || k.src.pendingCount() != 1 {
		t.Fatalf("pulled while spilling: fetches %d -> %d, pending %d", before, k.src.fetchCount(), k.src.pendingCount())
	}
	if k.c.Snapshot()[CounterSpills] != 1 {
		t.Fatalf("spills %v", k.c.Snapshot())
	}
	// Recovery: the queue drains, pulling resumes, every row arrives.
	k.store.setFail(nil)
	eventually(t, "both rows", func() bool { return len(k.store.rows(probeTable.Name)) == 2 })
	eventually(t, "ok", func() bool { return k.p.Snapshot().State == StateOK })
}

// E-10: the queue's row bound.
func TestQueueAtItsRowBoundStopsPulling(t *testing.T) {
	k := newKit(t, func(c *Config) { c.QueueMaxRows = 4; c.FetchMax = 1 })
	k.store.setFail(func([]ts.Part) error { return errors.New("database down") })
	for i := range 10 {
		k.src.add(rowsMsg(t, uint64(i+1), fmt.Sprintf("a%d", i), fmt.Sprintf("b%d", i)))
	}
	k.run(t)
	eventually(t, "spilling", func() bool { return k.p.Snapshot().State == StateSpilling })
	time.Sleep(50 * time.Millisecond)
	if s := k.p.Snapshot(); s.QueueRows > 4+2 || k.src.pendingCount() < 7 {
		t.Fatalf("queue past its bound: %+v pending %d", s, k.src.pendingCount())
	}
	k.store.setFail(nil)
	eventually(t, "all rows", func() bool { return len(k.store.rows(probeTable.Name)) == 20 })
	if got := k.c.Snapshot()[CounterRowsWritten]; got != 20 {
		t.Fatalf("written %d", got)
	}
}

// B-13: a step in the sequences that the stream no longer holds is a
// stream_retention gap, committed with the rows of the message after it.
func TestHoleInTheStreamIsRecordedWithTheNextRows(t *testing.T) {
	k := newKit(t, nil)
	k.src.holes = func(j []Jump) ([]Hole, error) {
		out := make([]Hole, len(j))
		for i, x := range j {
			if x.After == 1 && x.Before == 5 {
				out[i] = Hole{FromSeq: 2, ToSeq: 4, Count: 3}
			}
		}
		return out, nil
	}
	k.src.add(rowsMsg(t, 1, "a"), rowsMsg(t, 5, "b"))
	k.run(t)
	eventually(t, "gap", func() bool { return len(k.store.gaps()) == 1 })
	g := k.store.gaps()[0]
	if g["cause"] != CauseStreamRetention || g["from_seq"] != int64(2) || g["to_seq"] != int64(4) || g["count"] != int64(3) ||
		g["count_unit"] != ts.UnitMessages || g["stream"] != "TSW" || g["table_name"] != probeTable.Name {
		t.Fatalf("gap %v", g)
	}
	// The gap and the rows of seq 5 are one transaction.
	k.store.mu.Lock()
	var together bool
	for _, c := range k.store.commits {
		// rows, gaps, and the table's position (writer_positions)
		if len(c) == 3 && len(c[1].Rows) == 1 && len(c[0].Rows) >= 1 && c[0].Rows[len(c[0].Rows)-1][0] == "b" &&
			c[2].Table.Name == ts.WriterPositions.Name {
			together = true
		}
	}
	k.store.mu.Unlock()
	if !together {
		t.Fatal("gap not committed with the next rows")
	}
	if k.c.Snapshot()[CounterGapsObserved] != 1 || k.c.Snapshot()[CounterGaps] != 1 {
		t.Fatalf("counters %v", k.c.Snapshot())
	}
}

// E-01 pair: a step over other tables' messages, all still in the
// stream, is no hole.
func TestStepOverPresentMessagesIsNoGap(t *testing.T) {
	k := newKit(t, nil)
	k.src.add(rowsMsg(t, 1, "a"), rowsMsg(t, 7, "b"))
	k.run(t)
	eventually(t, "rows", func() bool { return len(k.store.rows(probeTable.Name)) == 2 })
	if len(k.store.gaps()) != 0 {
		t.Fatalf("gaps %v", k.store.gaps())
	}
	k.src.mu.Lock()
	defer k.src.mu.Unlock()
	if len(k.src.jumps) != 1 || k.src.jumps[0] != (Jump{After: 1, Before: 7}) {
		t.Fatalf("jumps %v", k.src.jumps)
	}
}

// The first delivery after a restart is compared with the ack floor.
func TestHoleAfterTheAckFloorIsChecked(t *testing.T) {
	k := newKit(t, nil)
	k.src.floor = 10
	k.src.add(rowsMsg(t, 15, "a"))
	k.run(t)
	eventually(t, "rows", func() bool { return len(k.store.rows(probeTable.Name)) == 1 })
	k.src.mu.Lock()
	defer k.src.mu.Unlock()
	if len(k.src.jumps) != 1 || k.src.jumps[0] != (Jump{After: 10, Before: 15}) {
		t.Fatalf("jumps %v", k.src.jumps)
	}
}

// A hole check that cannot run gives the messages back and advances
// nothing, so the hole is checked again on redelivery.
func TestFailedHoleCheckGivesTheMessagesBack(t *testing.T) {
	k := newKit(t, nil)
	var calls int
	k.src.holes = func(j []Jump) ([]Hole, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("stream info timed out")
		}
		return make([]Hole, len(j)), nil
	}
	m := rowsMsg(t, 3, "a")
	k.src.add(m)
	k.run(t)
	eventually(t, "nak", func() bool { _, n, _ := m.counts(); return n == 1 })
	if k.p.Snapshot().LastSeq != 0 {
		t.Fatal("advanced past an unchecked hole")
	}
	k.src.add(m) // redelivered
	eventually(t, "written", func() bool { a, _, _ := m.counts(); return a == 1 })
	if k.c.Snapshot()[CounterHoleCheckFailed] != 1 {
		t.Fatalf("counters %v", k.c.Snapshot())
	}
}

// A message the writer cannot read is a malformed gap with its row
// count, acknowledged with the record; the readable one beside it is
// written (E-01 pair inside one batch).
func TestMalformedMessageBecomesAGap(t *testing.T) {
	k := newKit(t, nil)
	bad := &fakeMsg{data: []byte(`{"table":"probe","rows":[{"id":"x"},{"id":"y","at":"2026-10-02T10:00:00Z"}]}`), seq: 1}
	good := rowsMsg(t, 2, "a")
	k.src.add(bad, good)
	k.run(t)
	eventually(t, "both acked", func() bool { a1, _, _ := bad.counts(); a2, _, _ := good.counts(); return a1 == 1 && a2 == 1 })
	gaps := k.store.gaps()
	if len(gaps) != 1 || gaps[0]["cause"] != CauseMalformed || gaps[0]["count"] != int64(2) || gaps[0]["count_unit"] != ts.UnitRows ||
		!strings.Contains(gaps[0]["detail"].(string), "at") {
		t.Fatalf("gaps %v", gaps)
	}
	if rows := k.store.rows(probeTable.Name); len(rows) != 1 || rows[0][0] != "a" {
		t.Fatalf("rows %v", rows)
	}
	unreadable := &fakeMsg{data: []byte("not json"), seq: 3}
	nometa := &fakeMsg{data: []byte(`{}`), noMeta: true}
	k.src.add(unreadable, nometa)
	eventually(t, "three gaps", func() bool { return len(k.store.gaps()) == 3 })
	for _, g := range k.store.gaps()[1:] {
		if g["count"] != int64(1) || g["count_unit"] != ts.UnitMessages {
			t.Fatalf("gap %v", g)
		}
	}
}

func dataError() error { return &pgconn.PgError{Code: "23514", Message: "check violation"} }

// One message the database refuses becomes a rejected gap; the others
// in its batch are written.
func TestRefusedRowsBecomeARejectedGapAndTheRestAreWritten(t *testing.T) {
	k := newKit(t, func(c *Config) { c.BatchMaxWait = 50 * time.Millisecond })
	k.store.setFail(func(parts []ts.Part) error {
		for _, r := range parts[0].Rows {
			if r[0] == "poison" {
				return dataError()
			}
		}
		return nil
	})
	m1, bad, m3 := rowsMsg(t, 1, "a"), rowsMsg(t, 2, "poison", "x"), rowsMsg(t, 3, "c")
	k.src.add(m1, bad, m3)
	k.run(t)
	eventually(t, "acks", func() bool {
		a1, _, _ := m1.counts()
		a2, _, _ := bad.counts()
		a3, _, _ := m3.counts()
		return a1 == 1 && a2 == 1 && a3 == 1
	})
	if rows := k.store.rows(probeTable.Name); len(rows) != 2 {
		t.Fatalf("rows %v", rows)
	}
	gaps := k.store.gaps()
	if len(gaps) != 1 || gaps[0]["cause"] != CauseRejected || gaps[0]["count"] != int64(2) || gaps[0]["from_seq"] != int64(2) {
		t.Fatalf("gaps %v", gaps)
	}
	if k.c.Snapshot()[CounterRowsRejected] != 2 || k.p.Snapshot().QueueRows != 0 {
		t.Fatalf("counters %v snapshot %+v", k.c.Snapshot(), k.p.Snapshot())
	}
}

// A rejected message whose gap record is refused too is counted and
// logged, never retried for ever.
func TestRejectedRecordRefusedIsCounted(t *testing.T) {
	k := newKit(t, nil)
	k.store.setFail(func([]ts.Part) error { return dataError() })
	m := rowsMsg(t, 1, "a")
	k.src.add(m)
	k.run(t)
	eventually(t, "ack", func() bool { a, _, _ := m.counts(); return a == 1 })
	if k.c.Snapshot()[CounterRejectedUnrecorded] != 1 || !strings.Contains(k.logs.String(), "rejected_unrecorded") {
		t.Fatalf("counters %v", k.c.Snapshot())
	}
}

// A message redelivered while it is still queued replaces its earlier
// delivery and is written once.
func TestRedeliveryWhileQueuedIsNotQueuedTwice(t *testing.T) {
	k := newKit(t, nil)
	k.store.setFail(func([]ts.Part) error { return errors.New("down") })
	first := rowsMsg(t, 1, "a")
	k.src.add(first)
	k.run(t)
	eventually(t, "queued", func() bool { return k.p.Snapshot().QueueRows == 1 })
	again := rowsMsg(t, 1, "a")
	k.src.add(again)
	eventually(t, "redelivery seen", func() bool { return k.c.Snapshot()[CounterRedelivered] == 1 })
	if s := k.p.Snapshot(); s.QueueMessages != 1 {
		t.Fatalf("queued twice: %+v", s)
	}
	k.store.setFail(nil)
	eventually(t, "acked", func() bool { a, _, _ := again.counts(); return a == 1 })
	if a, _, _ := first.counts(); a != 0 {
		t.Fatal("the stale delivery was acknowledged")
	}
}

// Held messages are kept from redelivery while writes fail.
func TestHeldMessagesAreKeptInProgress(t *testing.T) {
	k := newKit(t, func(c *Config) { c.AckWait = 2 * time.Second })
	k.store.setFail(func([]ts.Part) error { return errors.New("down") })
	m := rowsMsg(t, 1, "a")
	k.src.add(m)
	k.run(t)
	eventually(t, "queued", func() bool { return k.p.Snapshot().QueueRows == 1 })
	if _, _, ip := m.counts(); ip != 0 {
		t.Fatal("in progress before half the ack wait")
	}
	k.clk.advance(time.Second)
	eventually(t, "in progress", func() bool { _, _, ip := m.counts(); return ip >= 1 })
}

func TestFetchFailureIsCountedAndRetried(t *testing.T) {
	k := newKit(t, nil)
	k.src.fetchErr = errors.New("no responders")
	k.run(t)
	eventually(t, "fetch failures", func() bool { return k.c.Snapshot()[CounterFetchFailed] >= 2 })
}

func TestGapsPipelineWritesGapRecordsOnly(t *testing.T) {
	k := newKit(t, nil)
	k.p.Table, k.p.Decode = ts.WriterGaps, GapsDecoder
	g := ts.GapMessage{Table: "rid_observations", FromSeq: 7, ToSeq: 7, Cause: "ingest_queue_age", Count: 12,
		At: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC), ReceiverID: "rx-1"}
	b, _ := json.Marshal(g)
	hdr := nats.Header{}
	hdr.Set(jetstream.MsgIDHeader, "gap:ingest_queue_age:7:7")
	k.src.add(&fakeMsg{data: b, hdr: hdr, seq: 1})
	k.run(t)
	eventually(t, "gap", func() bool { return len(k.store.gaps()) == 1 })
	got := k.store.gaps()[0]
	if got["dedupe_key"] != "msg:gap:ingest_queue_age:7:7" || got["stream"] != "INGEST" || got["count_unit"] != ts.UnitRows ||
		got["receiver_id"] != "rx-1" || got["count"] != int64(12) {
		t.Fatalf("gap %v", got)
	}
	k.store.mu.Lock()
	defer k.store.mu.Unlock()
	for _, c := range k.store.commits {
		// gap records, and the table's position
		if len(c) != 2 || c[0].Table.Name != ts.WriterGaps.Name || c[1].Table.Name != ts.WriterPositions.Name {
			t.Fatalf("commit %v", c)
		}
	}
	if k.c.Snapshot()[CounterGaps] != 1 || k.c.Snapshot()[CounterRowsWritten] != 0 {
		t.Fatalf("counters %v", k.c.Snapshot())
	}
}

func TestGapsDecoderKeysAndDefaults(t *testing.T) {
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	enc := func(g ts.GapMessage) []byte { b, _ := json.Marshal(g); return b }
	hdr := nats.Header{}
	hdr.Set(jetstream.MsgIDHeader, "gap:x:3:4")
	// Sequenced with a message id: keyed by the id.
	rows, _, err := GapsDecoder(&fakeMsg{data: enc(ts.GapMessage{Table: "t", FromSeq: 3, ToSeq: 4, Cause: "x", Count: 1, At: at}), hdr: hdr}, 9)
	if err != nil || rows[0][0] != "msg:gap:x:3:4" {
		t.Fatalf("%v %v", rows, err)
	}
	// Unsequenced (a corrupt queue message has from_seq 0): keyed by the
	// TSW sequence, so two such records are two holes.
	rows, _, err = GapsDecoder(&fakeMsg{data: enc(ts.GapMessage{Table: "t", Cause: "x", Count: 1, At: at, Stream: "OTHER", CountUnit: ts.UnitMessages}), hdr: hdr}, 9)
	if err != nil || rows[0][0] != "tsw:9" || rows[0][2] != "OTHER" || rows[0][7] != ts.UnitMessages {
		t.Fatalf("%v %v", rows, err)
	}
	for name, g := range map[string]ts.GapMessage{
		"no table":      {Cause: "x", At: at},
		"no cause":      {Table: "t", At: at},
		"no time":       {Table: "t", Cause: "x"},
		"backwards":     {Table: "t", Cause: "x", At: at, FromSeq: 5, ToSeq: 4},
		"negative":      {Table: "t", Cause: "x", At: at, Count: -1},
		"unknown unit":  {Table: "t", Cause: "x", At: at, CountUnit: "bytes"},
		"accepted twin": {Table: "t", Cause: "x", At: at},
	} {
		_, _, err := GapsDecoder(&fakeMsg{data: enc(g)}, 1)
		if (name == "accepted twin") != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, _, err := GapsDecoder(&fakeMsg{data: []byte("[")}, 1); err == nil {
		t.Fatal("not JSON accepted")
	}
}

func TestRowsDecoderRefusesAnotherTableAndNoRows(t *testing.T) {
	dec := RowsDecoder(probeTable)
	for name, body := range map[string]string{
		"other table":  `{"table":"other","rows":[{"id":"a","at":"2026-10-02T10:00:00Z"}]}`,
		"no rows":      `{"table":"probe","rows":[]}`,
		"not object":   `[1]`,
		"unknown cell": `{"table":"probe","rows":[{"id":"a","at":"2026-10-02T10:00:00Z","extra":1}]}`,
	} {
		if _, _, err := dec(&fakeMsg{data: []byte(body)}, 1); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	rows, _, err := dec(&fakeMsg{data: []byte(`{"table":"probe","rows":[{"id":"a","at":"2026-10-02T12:00:00+02:00"}]}`)}, 1)
	if err != nil || rows[0][1] != time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC) {
		t.Fatalf("%v %v", rows, err)
	}
}

func TestHolesOf(t *testing.T) {
	cases := []struct {
		name    string
		jump    Jump
		first   uint64
		deleted []uint64
		want    Hole
	}{
		{"all present", Jump{After: 3, Before: 9}, 1, nil, Hole{}},
		{"head aged out", Jump{After: 3, Before: 9}, 7, nil, Hole{FromSeq: 4, ToSeq: 6, Count: 3}},
		{"all of it aged out", Jump{After: 3, Before: 9}, 20, nil, Hole{FromSeq: 4, ToSeq: 8, Count: 5}},
		{"interior deletes", Jump{After: 3, Before: 9}, 1, []uint64{2, 5, 6, 9}, Hole{FromSeq: 5, ToSeq: 6, Count: 2}},
		{"head and interior", Jump{After: 3, Before: 12}, 6, []uint64{8, 13}, Hole{FromSeq: 4, ToSeq: 8, Count: 3}},
		{"from the start", Jump{After: 0, Before: 4}, 4, nil, Hole{FromSeq: 1, ToSeq: 3, Count: 3}},
	}
	for _, c := range cases {
		if got := holesOf([]Jump{c.jump}, c.first, c.deleted)[0]; got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

func TestStatusNamesTheWorstState(t *testing.T) {
	ok, spill, fail := &Pipeline{Table: probeTable}, &Pipeline{Table: probeTable, spilling: true}, &Pipeline{Table: probeTable, failing: true}
	ret := &Retention{}
	state := func(ps ...*Pipeline) string {
		for _, a := range Status(ps, ret)() {
			if a.Key == "writer_state" {
				return a.Value.String()
			}
		}
		return ""
	}
	if state(ok) != StateOK || state(ok, fail) != StateWriteFailing || state(fail, spill) != StateSpilling || state(spill, fail) != StateSpilling {
		t.Fatal("state")
	}
}

// purgeGaps are the committed stream_purge records.
func (s *fakeStore) purgeGaps() []map[string]any {
	var out []map[string]any
	for _, g := range s.gaps() {
		if g["cause"] == CauseStreamPurge {
			out = append(out, g)
		}
	}
	return out
}

// Every batch commits the table's position with its rows: the highest
// stream sequence it covers.
func TestEveryWriteCommitsTheTablePosition(t *testing.T) {
	k := newKit(t, nil)
	k.src.add(rowsMsg(t, 1, "a"), rowsMsg(t, 2, "b"))
	k.run(t)
	eventually(t, "rows", func() bool { return len(k.store.rows(probeTable.Name)) == 2 })
	eventually(t, "position", func() bool {
		seq, known, _ := k.store.Position(context.Background(), probeTable.Name, "TSW")
		return known && seq == 2
	})
	if len(k.store.purgeGaps()) != 0 || k.c.Get(CounterRowsWritten) != 2 {
		t.Fatalf("gaps %v counters %v", k.store.gaps(), k.c.Snapshot())
	}
}

// A purge while the writer was down (B-13): the consumer's ack floor is
// past the position written, so the purged sequences are a stream_purge
// gap, committed with the new position before anything is pulled. The
// twin: a floor equal to the position records nothing (E-01).
func TestPurgeWhileDownIsRecordedAtStart(t *testing.T) {
	for _, tc := range []struct {
		name  string
		floor uint64
		purge bool
	}{{"purged", 7, true}, {"not purged", 3, false}} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKit(t, nil)
			k.store.preset, k.store.presetKnown = 3, true
			k.src.setFloor(tc.floor)
			k.src.add(rowsMsg(t, tc.floor+1, "a"))
			k.run(t)
			eventually(t, "rows", func() bool { return len(k.store.rows(probeTable.Name)) == 1 })
			gaps := k.store.purgeGaps()
			if !tc.purge {
				if len(gaps) != 0 || k.c.Get(CounterPurgesObserved) != 0 {
					t.Fatalf("purge recorded without a purge: %v", gaps)
				}
				return
			}
			if len(gaps) != 1 {
				t.Fatalf("gaps %v", k.store.gaps())
			}
			g := gaps[0]
			if g["from_seq"] != int64(4) || g["to_seq"] != int64(7) || g["count"] != int64(4) || g["count_unit"] != ts.UnitMessages ||
				g["stream"] != "TSW" || g["dedupe_key"] != "tsw:stream_purge:probe:4-7" || k.c.Get(CounterPurgesObserved) != 1 {
				t.Fatalf("gap %v counters %v", g, k.c.Snapshot())
			}
			k.store.mu.Lock()
			first := k.store.commits[0]
			k.store.mu.Unlock()
			if len(first) != 2 || first[0].Table.Name != ts.WriterGaps.Name || first[1].Rows[0][2] != int64(7) {
				t.Fatalf("the purge record and the position are not one commit: %v", first)
			}
			if k.src.fetchCount() == 0 {
				t.Fatal("not pulled after the record")
			}
		})
	}
}

// A purge while the writer runs: messages never delivered are skipped by
// the consumer's floor, the next delivery steps over them. The step up to
// the floor is a stream_purge gap and only what lies beyond it is checked
// for retention.
func TestPurgeWhileRunningIsRecordedAtTheNextDelivery(t *testing.T) {
	k := newKit(t, func(c *Config) { c.PurgeCheck = time.Hour })
	k.src.add(rowsMsg(t, 1, "a"))
	k.run(t)
	eventually(t, "first", func() bool { return len(k.store.rows(probeTable.Name)) == 1 })
	k.src.setFloor(5) // 2..5 purged before delivery
	k.src.add(rowsMsg(t, 6, "b"))
	eventually(t, "second", func() bool { return len(k.store.rows(probeTable.Name)) == 2 })
	gaps := k.store.purgeGaps()
	if len(gaps) != 1 || gaps[0]["from_seq"] != int64(2) || gaps[0]["to_seq"] != int64(5) {
		t.Fatalf("gaps %v", k.store.gaps())
	}
	k.src.mu.Lock()
	jumps := append([]Jump(nil), k.src.jumps...)
	k.src.mu.Unlock()
	if len(jumps) != 1 || jumps[0] != (Jump{After: 5, Before: 6}) {
		t.Fatalf("retention checked over %v, want only past the floor", jumps)
	}
}

// A purge of undelivered messages with nothing after it: the idle
// consumer's floor check records it while the consumer is behind
// (messages of its table undelivered, here held back as by
// max_ack_pending). The twin (review of PR #14): a purge while the
// consumer is caught up removes none of its messages; it is counted,
// not recorded, so a quiet table never records a purge.
func TestIdlePurgeIsRecorded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending uint64
		record  bool
	}{{"behind", 3, true}, {"caught up", 0, false}} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKit(t, func(c *Config) { c.PurgeCheck = time.Millisecond })
			k.src.add(rowsMsg(t, 1, "a"))
			k.src.setLast(1, tc.pending)
			k.run(t)
			eventually(t, "first", func() bool { return len(k.store.rows(probeTable.Name)) == 1 })
			eventually(t, "idle checks", func() bool { return k.src.fetchCount() > 10 })
			if len(k.store.purgeGaps()) != 0 {
				t.Fatal("purge recorded on an idle consumer with no purge")
			}
			k.src.setLast(4, 0)
			k.src.setFloor(4)
			if tc.record {
				eventually(t, "purge", func() bool { return len(k.store.purgeGaps()) == 1 })
				if g := k.store.purgeGaps()[0]; g["from_seq"] != int64(2) || g["to_seq"] != int64(4) {
					t.Fatalf("gap %v", g)
				}
			} else {
				eventually(t, "counted", func() bool { return k.c.Get(CounterPurgeCaughtUp) == 1 })
				if len(k.store.purgeGaps()) != 0 {
					t.Fatalf("a caught-up consumer recorded %v", k.store.purgeGaps())
				}
			}
			eventually(t, "last_seq", func() bool { return k.p.Snapshot().LastSeq == 4 })
		})
	}
}

// A position that cannot be read holds the writes, never silently: the
// state is write_failing and it is counted, so a purge while the writer
// was down cannot slip by; once it can be read the rows are written.
func TestUnreadablePositionHoldsTheWrites(t *testing.T) {
	k := newKit(t, nil)
	k.store.mu.Lock()
	k.store.posErr = errors.New("database unavailable")
	k.store.mu.Unlock()
	k.src.add(rowsMsg(t, 1, "a"))
	k.run(t)
	eventually(t, "counted", func() bool { return k.c.Get(CounterPositionFailed) > 0 && k.p.Snapshot().State == StateWriteFailing })
	if len(k.store.rows(probeTable.Name)) != 0 {
		t.Fatal("written without the position check")
	}
	k.store.mu.Lock()
	k.store.posErr = nil
	k.store.mu.Unlock()
	eventually(t, "rows", func() bool { return len(k.store.rows(probeTable.Name)) == 1 && k.p.Snapshot().State == StateOK })
}

// A purge whose record cannot be written gives the delivered messages
// back and advances nothing; it is recorded once the store returns.
func TestUnwrittenPurgeRecordGivesTheMessagesBack(t *testing.T) {
	k := newKit(t, func(c *Config) { c.PurgeCheck = time.Hour })
	k.src.add(rowsMsg(t, 1, "a"))
	k.run(t)
	eventually(t, "first", func() bool { return len(k.store.rows(probeTable.Name)) == 1 })
	k.store.setFail(func(parts []ts.Part) error {
		if parts[0].Table.Name == ts.WriterGaps.Name && len(parts[0].Rows) > 0 && parts[0].Rows[0][5] == CauseStreamPurge {
			return errors.New("connection reset")
		}
		return nil
	})
	k.src.setFloor(3)
	m := rowsMsg(t, 4, "b")
	k.src.add(m)
	eventually(t, "nak", func() bool { _, n, _ := m.counts(); return n >= 1 })
	if len(k.store.purgeGaps()) != 0 || k.p.Snapshot().LastSeq != 1 {
		t.Fatalf("advanced past an unrecorded purge: %v", k.p.Snapshot())
	}
	k.store.setFail(nil)
	k.src.add(m)
	eventually(t, "recorded", func() bool { return len(k.store.purgeGaps()) == 1 && len(k.store.rows(probeTable.Name)) == 2 })
}

// WP-9's false stream_retention on a quiet table (review of PR #14): a
// table whose consumer was caught up while the other tables' messages
// aged out of the stream steps over those sequences at its next
// delivery; none was its own, so nothing is recorded. The twin: a
// consumer with messages pending (not caught up) records the hole.
func TestQuietTableRecordsNoRetentionGap(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending uint64
		gap     bool
	}{{"caught up", 0, false}, {"behind", 3, true}} {
		t.Run(tc.name, func(t *testing.T) {
			k := newKit(t, func(c *Config) { c.PurgeCheck = time.Millisecond })
			k.src.holes = func(j []Jump) ([]Hole, error) { // everything stepped over is gone
				out := make([]Hole, len(j))
				for i, jj := range j {
					if jj.Before > jj.After+1 {
						out[i] = Hole{FromSeq: jj.After + 1, ToSeq: jj.Before - 1, Count: jj.Before - jj.After - 1}
					}
				}
				return out, nil
			}
			k.src.add(rowsMsg(t, 1, "a"))
			k.run(t)
			eventually(t, "first", func() bool { return len(k.store.rows(probeTable.Name)) == 1 })
			// Other tables' messages 2..49 arrive and age out while this
			// table is idle and caught up (or not).
			k.src.setLast(49, tc.pending)
			eventually(t, "idle checks", func() bool { return k.src.fetchCount() > 20 })
			k.src.add(rowsMsg(t, 50, "b"))
			eventually(t, "second", func() bool { return len(k.store.rows(probeTable.Name)) == 2 })
			var retention int
			for _, g := range k.store.gaps() {
				if g["cause"] == CauseStreamRetention {
					retention++
				}
			}
			if (retention > 0) != tc.gap {
				t.Fatalf("retention gaps %v, want a gap %v", k.store.gaps(), tc.gap)
			}
		})
	}
}
