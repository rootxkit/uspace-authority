package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/tswriter"
)

// These tests run tsdb-writer as a process against a real NATS
// JetStream and TimescaleDB (INTEGRATION=1, NATS_URL, TS_URL). Each
// starts from a deleted TSW stream (its consumers go with it) and a
// scratch telemetry database; they run one after another (go test -p 1).
// A stopped database is a TCP proxy that cuts every connection and
// refuses new ones, so the outage runs in CI without Docker control.

// lines is a goroutine-safe stdout read back as JSON log lines.
type lines struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lines) all(msg string) []map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(l.b.Bytes()))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil && m["msg"] == msg {
			out = append(out, m)
		}
	}
	return out
}

func (l *lines) tail(n int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	all := strings.Split(strings.TrimRight(l.b.String(), "\n"), "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return strings.Join(all, "\n")
}

func (l *lines) waitFor(t *testing.T, d time.Duration, msg string, ok func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, m := range l.all(msg) {
			if ok == nil || ok(m) {
				return m
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no %q line in %s; last lines:\n%s", msg, d, l.tail(30))
	return nil
}

// status is one status line's writer view.
type status struct {
	State    string
	Tables   []tswriter.Snapshot
	Counters map[string]float64
}

func parseStatus(m map[string]any) status {
	var s status
	s.State, _ = m["writer_state"].(string)
	raw, _ := json.Marshal(m["tables"])
	_ = json.Unmarshal(raw, &s.Tables)
	s.Counters = map[string]float64{}
	if c, ok := m["counters"].(map[string]any); ok {
		if w, ok := c["tsdb_writer"].(map[string]any); ok {
			for k, v := range w {
				s.Counters[k], _ = v.(float64)
			}
		}
	}
	return s
}

// proxy forwards TCP to target until down cuts it.
type proxy struct {
	ln     net.Listener
	target string
	mu     sync.Mutex
	isDown bool
	conns  map[net.Conn]bool
}

func newProxy(t *testing.T, target string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln, target: target, conns: map[net.Conn]bool{}}
	t.Cleanup(func() { _ = ln.Close(); p.down() })
	go p.serve()
	return p
}

func (p *proxy) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		if p.isDown {
			p.mu.Unlock()
			_ = c.Close()
			continue
		}
		up, err := net.Dial("tcp", p.target)
		if err != nil {
			p.mu.Unlock()
			_ = c.Close()
			continue
		}
		p.conns[c], p.conns[up] = true, true
		p.mu.Unlock()
		go func() { _, _ = io.Copy(up, c); _ = up.Close(); _ = c.Close() }()
		go func() { _, _ = io.Copy(c, up); _ = up.Close(); _ = c.Close() }()
	}
}

// down closes every forwarded connection and refuses new ones.
func (p *proxy) down() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isDown = true
	for c := range p.conns {
		_ = c.Close()
	}
	p.conns = map[net.Conn]bool{}
}

func (p *proxy) up() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.isDown = false
}

type harness struct {
	t      *testing.T
	js     jetstream.JetStream
	dbURL  string
	db     *sql.DB
	stdout *lines
	exit   chan int
	cancel context.CancelFunc
	frames atomic.Int64
}

func natsURL(t *testing.T) string {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs NATS JetStream and TimescaleDB (make up)")
	}
	u := os.Getenv("NATS_URL")
	if u == "" {
		t.Fatal("INTEGRATION=1 but NATS_URL is unset")
	}
	return u
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	nc, err := nats.Connect(natsURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	if err := js.DeleteStream(context.Background(), bus.StreamTSW); err != nil && !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatal(err)
	}
	u := storetest.Migrated(t, migrate.Timeseries)
	return &harness{t: t, js: js, dbURL: u, db: storetest.Open(t, u)}
}

// via is the database URL through p.
func (h *harness) via(p *proxy) string {
	u, err := url.Parse(h.dbURL)
	if err != nil {
		h.t.Fatal(err)
	}
	u.Host = p.ln.Addr().String()
	return u.String()
}

func (h *harness) target() string {
	u, err := url.Parse(h.dbURL)
	if err != nil {
		h.t.Fatal(err)
	}
	return u.Host
}

func (h *harness) start(extra map[string]string, o tswriter.Options) {
	h.t.Helper()
	m := map[string]string{
		"NATS_URL": natsURL(h.t), "TS_URL": h.dbURL, "ADMIN_ADDR": "127.0.0.1:0", "STATUS_INTERVAL_S": "1",
		"SHUTDOWN_TIMEOUT_S": "10", "TSDB_WRITER_RETRY_MAX_MS": "500", "TSDB_WRITER_WRITE_TIMEOUT_S": "5",
	}
	for k, v := range extra {
		m[k] = v
	}
	if o.DatabaseRetry == 0 {
		o.DatabaseRetry = 200 * time.Millisecond
	}
	h.stdout = &lines{}
	ctx, cancel := context.WithCancel(context.Background())
	exit, out := make(chan int, 1), h.stdout
	h.cancel, h.exit = cancel, exit
	go func() {
		exit <- proc.Main(ctx, specWith(&config.TSDBWriter{}, o), nil, out, io.Discard,
			func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	}()
	h.t.Cleanup(func() {
		cancel()
		select {
		case code, ok := <-exit:
			if ok && code != proc.ExitOK {
				h.t.Errorf("exit %d; last lines:\n%s", code, out.tail(40))
			}
		case <-time.After(30 * time.Second):
			h.t.Error("tsdb-writer did not stop")
		}
	})
	out.waitFor(h.t, 20*time.Second, "tsdb-writer consuming", nil)
}

// stop stops the writer and waits for its exit.
func (h *harness) stop() {
	h.t.Helper()
	h.cancel()
	select {
	case code := <-h.exit:
		if code != proc.ExitOK {
			h.t.Fatalf("exit %d; last lines:\n%s", code, h.stdout.tail(40))
		}
		close(h.exit)
	case <-time.After(30 * time.Second):
		h.t.Fatal("tsdb-writer did not stop")
	}
}

// batch is n rid_observations rows of one receiver batch, each with a
// fresh frame id.
func (h *harness) batch(n int) *ridpipe.Batch {
	now := time.Now().UTC()
	b := &ridpipe.Batch{ID: fmt.Sprintf("rx-wp9:%d", h.frames.Load()), ReceiverID: "rx-wp9", IngestTS: now, Nonce: "n"}
	for range n {
		i := h.frames.Add(1)
		payload := []byte{0x12, byte(i >> 16), byte(i >> 8), byte(i)}
		sum := sha256.Sum256(payload)
		frame := sha256.Sum256(fmt.Appendf(nil, "rx-wp9|%d", i))
		rx := now.Add(-time.Duration(i%1000) * time.Millisecond)
		mt := 1
		b.Rows = append(b.Rows, ridpipe.Row{
			IngestTS: now, FrameID: hex.EncodeToString(frame[:16]), ReceiverID: "rx-wp9", Transmitter: fmt.Sprintf("TEST%04d", i%20),
			ReceiverTS: &rx, MsgType: &mt, Payload: payload, PayloadSHA256: sum[:], SentAtMS: now.UnixMilli(), Nonce: "n",
		})
	}
	return b
}

// put hands a batch over exactly as rid-ingest does (WP-7's JetRows).
func (h *harness) put(b *ridpipe.Batch) {
	h.t.Helper()
	if err := (ingest.JetRows{JS: h.js, Timeout: 5 * time.Second}).PutRows(context.Background(), b); err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) count(sqlText string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(sqlText).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *harness) rows() (total, distinct int) {
	return h.count(`SELECT count(*) FROM rid_observations`), h.count(`SELECT count(DISTINCT frame_id) FROM rid_observations`)
}

func waitUntil(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not met in %s", what, d)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// lastStatus waits for a status line that ok accepts.
func (h *harness) lastStatus(d time.Duration, ok func(status) bool) status {
	h.t.Helper()
	var s status
	h.stdout.waitFor(h.t, d, "status", func(m map[string]any) bool { s = parseStatus(m); return ok(s) })
	return s
}

// E-02, B-05: the success path end to end. rid-ingest's own publisher
// hands rows and a gap record over; the writer stores them, reads back,
// and a redelivered batch (a new message id, past the stream's
// duplicate window) writes nothing twice. ts.BusWriter, the adapters'
// hand-over, is read back the same way. No stream_retention gap is
// recorded where nothing was lost (the twin of the forced gap below).
func TestIntegrationRowsAreWrittenOnceAndReadBack(t *testing.T) {
	h := newHarness(t)
	h.start(nil, tswriter.Options{})
	b := h.batch(5)
	h.put(b)
	again := *b
	again.ID = "rx-wp9:redelivered"
	h.put(&again)
	if err := (ingest.JetRows{JS: h.js, Timeout: 5 * time.Second}).PutGap(context.Background(), ingest.Gap{
		Table: ingest.RowsTable, FromSeq: 41, ToSeq: 41, Cause: ingest.CauseQueueAge, Count: 7, At: time.Now().UTC(), ReceiverID: "rx-wp9",
	}); err != nil {
		t.Fatal(err)
	}
	more := h.batch(3)
	if err := (ts.BusWriter{JS: h.js, Timeout: 5 * time.Second}).Enqueue(context.Background(), "rid_observations", more.Rows, "bw:1"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 20*time.Second, "8 rows", func() bool { n, _ := h.rows(); return n == 8 })
	s := h.lastStatus(10*time.Second, func(s status) bool {
		return s.Counters[tswriter.CounterRowsWritten] == 8 && s.Counters[tswriter.CounterGaps] == 1
	})
	if s.State != tswriter.StateOK || s.Counters[tswriter.CounterRowsDeduplicated] != 5 {
		t.Fatalf("status %+v", s)
	}
	if total, distinct := h.rows(); total != 8 || distinct != 8 {
		t.Fatalf("rows %d distinct %d", total, distinct)
	}
	var cause, stream, unit, rx string
	var count int
	if err := h.db.QueryRow(`SELECT cause, stream, count, count_unit, receiver_id FROM writer_gaps`).Scan(&cause, &stream, &count, &unit, &rx); err != nil ||
		cause != ingest.CauseQueueAge || stream != "INGEST" || count != 7 || unit != "rows" || rx != "rx-wp9" {
		t.Fatalf("gap %s %s %d %s %s %v", cause, stream, count, unit, rx, err)
	}
	if n := h.count(`SELECT count(*) FROM writer_gaps WHERE cause = 'stream_retention'`); n != 0 {
		t.Fatalf("%d stream_retention gaps with nothing lost", n)
	}
}

// gapRows lists writer_gaps as "table stream from-to count unit cause".
func (h *harness) gapRows() []string {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT table_name, stream, from_seq, to_seq, count, count_unit, cause FROM writer_gaps ORDER BY from_seq`)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var table, stream, unit, cause string
		var from, to, count int
		if err := rows.Scan(&table, &stream, &from, &to, &count, &unit, &cause); err != nil {
			h.t.Fatal(err)
		}
		got = append(got, fmt.Sprintf("%s %s %d-%d %d %s %s", table, stream, from, to, count, unit, cause))
	}
	return got
}

// B-13: a forced sequence gap. While the writer is stopped, messages
// age out of the TSW stream (its age limit shortened to 4 s here, 10
// min in production) and one is deleted inside it; on restart the
// writer records both holes in writer_gaps with their sequences and
// counts, and writes the messages still there.
func TestIntegrationForcedSequenceGapIsRecorded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cfg, _ := bus.NewTopology(bus.DefaultLimits()).Stream(bus.StreamTSW)
	cfg.MaxAge, cfg.Duplicates = 4*time.Second, time.Second
	s, err := h.js.CreateStream(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.start(nil, tswriter.Options{})
	h.put(h.batch(2)) // seq 1
	waitUntil(t, 20*time.Second, "first rows", func() bool { n, _ := h.rows(); return n == 2 })
	h.stop()
	h.put(h.batch(2)) // seq 2
	h.put(h.batch(2)) // seq 3
	waitUntil(t, 20*time.Second, "seq 2 and 3 aged out", func() bool {
		info, err := s.Info(ctx)
		return err == nil && info.State.FirstSeq > 3
	})
	for range 3 {
		h.put(h.batch(2)) // seq 4, 5, 6
	}
	if err := s.DeleteMsg(ctx, 5); err != nil {
		t.Fatal(err)
	}
	h.start(nil, tswriter.Options{})
	waitUntil(t, 10*time.Second, "rows of seq 4 and 6", func() bool { n, _ := h.rows(); return n == 6 })
	waitUntil(t, 10*time.Second, "two gaps", func() bool { return h.count(`SELECT count(*) FROM writer_gaps`) >= 2 })
	want := []string{"rid_observations TSW 2-3 2 messages stream_retention", "rid_observations TSW 5-5 1 messages stream_retention"}
	if got := h.gapRows(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("gaps %v", got)
	}
	h.stdout.waitFor(t, 5*time.Second, "hole in the TSW stream: messages aged out before they were written", nil)
	h.lastStatus(10*time.Second, func(s status) bool { return s.Counters[tswriter.CounterGapsObserved] == 2 })
}

// B-13, WP-8: a purge of the TSW stream while the writer is stopped
// moves its consumers past the purged messages, so the writer is
// delivered no step; the floor is compared with the position the table
// was written to (writer_positions) and the purge recorded as a
// stream_purge gap at restart. The twin first: a restart without a
// purge records nothing (E-01).
func TestIntegrationPurgeWhileStoppedIsRecorded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.start(nil, tswriter.Options{})
	h.put(h.batch(2)) // seq 1
	waitUntil(t, 20*time.Second, "first rows", func() bool { n, _ := h.rows(); return n == 2 })
	waitUntil(t, 10*time.Second, "position", func() bool {
		return h.count(`SELECT count(*) FROM writer_positions WHERE table_name = 'rid_observations' AND stream = 'TSW' AND last_seq = 1`) == 1
	})
	h.stop()
	h.start(nil, tswriter.Options{})
	h.put(h.batch(2)) // seq 2
	waitUntil(t, 20*time.Second, "rows after a clean restart", func() bool { n, _ := h.rows(); return n == 4 })
	if g := h.gapRows(); len(g) != 0 {
		t.Fatalf("a restart without a purge recorded %v", g)
	}
	h.stop()
	for range 3 {
		h.put(h.batch(2)) // seq 3, 4, 5: never delivered
	}
	s, err := h.js.Stream(ctx, bus.StreamTSW)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Purge(ctx); err != nil {
		t.Fatal(err)
	}
	h.start(nil, tswriter.Options{})
	waitUntil(t, 10*time.Second, "purge gap", func() bool { return h.count(`SELECT count(*) FROM writer_gaps`) >= 1 })
	want := "rid_observations TSW 3-5 3 messages stream_purge"
	if got := h.gapRows(); len(got) != 1 || got[0] != want {
		t.Fatalf("gaps %v, want %s", got, want)
	}
	h.stdout.waitFor(t, 5*time.Second, "TSW stream purged: messages never delivered to this table were removed; recorded as a gap", nil)
	h.put(h.batch(2)) // seq 6: written, no further gap
	waitUntil(t, 20*time.Second, "rows after the purge", func() bool { n, _ := h.rows(); return n == 6 })
	time.Sleep(500 * time.Millisecond)
	if got := h.gapRows(); len(got) != 1 {
		t.Fatalf("gaps after the purge %v", got)
	}
	h.lastStatus(10*time.Second, func(s status) bool { return s.Counters[tswriter.CounterPurgesObserved] == 1 })
}

// traffic publishes n records on another table (writer_gaps) every
// interval: the busy table whose messages age out around a quiet one.
func (h *harness) traffic(n int, every time.Duration) {
	h.t.Helper()
	for i := range n {
		g := ts.GapMessage{Table: "other_table", FromSeq: 0, ToSeq: 0, Cause: "test_traffic", Count: 1, At: time.Now().UTC(),
			Detail: fmt.Sprint(i)}
		data, _ := json.Marshal(g)
		if _, err := h.js.Publish(context.Background(), "tsw.v1.writer_gaps", data); err != nil {
			h.t.Fatal(err)
		}
		time.Sleep(every)
	}
}

// quietGaps are the gap records of rid_observations other than the
// traffic's.
func (h *harness) quietGaps() []string {
	var out []string
	for _, g := range h.gapRows() {
		if strings.HasPrefix(g, "rid_observations ") {
			out = append(out, g)
		}
	}
	return out
}

// Review of PR #14, measured on the compose stack's nats-server: a
// filtered consumer's ack floor does not move when its own last message
// ages out of the stream, nor when other tables' messages do, so a quiet
// table is never mistaken for a purge. And a quiet table records no gap
// at all: neither while the writer runs (the idle check finds it caught
// up and moves past the aged-out sequences) nor after a restart (the
// last sequence accounted for is kept in writer_positions). Messages
// that age out while the writer is stopped are another matter: whose
// they were cannot be read, so they are recorded as an upper bound
// (TestIntegrationForcedSequenceGapIsRecorded). TSW ages
// messages out after 4 s here, 10 min in production. The twin, a real
// loss recorded, is TestIntegrationForcedSequenceGapIsRecorded.
func TestIntegrationQuietTableRecordsNoGap(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	cfg, _ := bus.NewTopology(bus.DefaultLimits()).Stream(bus.StreamTSW)
	cfg.MaxAge, cfg.Duplicates = 4*time.Second, time.Second
	s, err := h.js.CreateStream(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.start(nil, tswriter.Options{})
	h.put(h.batch(2)) // seq 1, then rid_observations is quiet
	waitUntil(t, 20*time.Second, "first rows", func() bool { n, _ := h.rows(); return n == 2 })
	h.traffic(24, 500*time.Millisecond) // 12 s of the other table; seq 1 and the oldest age out
	c, err := s.Consumer(ctx, tswriter.ConsumerPrefix+"rid_observations")
	if err != nil {
		t.Fatal(err)
	}
	ci, err := c.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	si, _ := s.Info(ctx)
	t.Logf("quiet consumer after its message and others aged out: ack floor %d, stream first %d last %d",
		ci.AckFloor.Stream, si.State.FirstSeq, si.State.LastSeq)
	if ci.AckFloor.Stream != 1 || si.State.FirstSeq <= 2 {
		t.Fatalf("ack floor %d, stream first %d: the measurement this test rests on changed", ci.AckFloor.Stream, si.State.FirstSeq)
	}
	h.put(h.batch(2)) // the quiet table speaks again, past the aged-out sequences
	waitUntil(t, 20*time.Second, "rows while running", func() bool { n, _ := h.rows(); return n == 4 })
	if g := h.quietGaps(); len(g) != 0 {
		t.Fatalf("a quiet table recorded %v while the writer ran", g)
	}
	h.traffic(24, 500*time.Millisecond) // 12 s more, aging out past the last delivery
	time.Sleep(11 * time.Second)        // an idle check stores the mark
	h.stop()
	h.start(nil, tswriter.Options{})
	h.put(h.batch(2))
	waitUntil(t, 20*time.Second, "rows after a restart", func() bool { n, _ := h.rows(); return n == 6 })
	time.Sleep(time.Second)
	if g := h.quietGaps(); len(g) != 0 {
		t.Fatalf("a quiet table recorded %v after a restart", g)
	}
}

// SC-18 as the writer sees it, E-02: the database is stopped for 60 s
// while rows keep arriving, then started. The queue fills to its bound
// and the writer spills (stops pulling, counted); after recovery every
// row arrives, none twice, no gap is recorded, and the status line says
// ok with an empty queue.
func TestIntegrationSC18DatabaseDownSixtySecondsLosesNothing(t *testing.T) {
	h := newHarness(t)
	p := newProxy(t, h.target())
	h.start(map[string]string{"TS_URL": h.via(p)}, tswriter.Options{})
	ctx, stop := context.WithCancel(context.Background())
	var sent atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				b := h.batch(20)
				if err := (ingest.JetRows{JS: h.js, Timeout: 5 * time.Second}).PutRows(context.Background(), b); err != nil {
					t.Error(err)
					return
				}
				sent.Add(20)
			}
		}
	}()
	waitUntil(t, 20*time.Second, "rows before the outage", func() bool { n, _ := h.rows(); return n > 0 })
	// The outage is the proxy cutting the database off; with
	// SC18_DOCKER_CONTAINER set (a manual run against a private stack)
	// the TimescaleDB container itself is stopped and started.
	down, up := p.down, p.up
	if c := os.Getenv("SC18_DOCKER_CONTAINER"); c != "" {
		docker := func(args ...string) {
			if out, err := exec.Command("docker", args...).CombinedOutput(); err != nil {
				t.Fatalf("docker %v: %v %s", args, err, out)
			}
		}
		down = func() { docker("stop", "-t", "5", c) }
		up = func() {
			docker("start", c)
			waitUntil(t, 60*time.Second, "database back", func() bool { return h.db.Ping() == nil })
		}
		t.Logf("outage: docker stop/start %s", c)
	}
	t.Log("database stopped")
	downAt := time.Now()
	down()
	h.stdout.waitFor(t, 30*time.Second, "writer queue at its bound: not pulling, rows wait in JetStream (spilling)", nil)
	h.lastStatus(10*time.Second, func(s status) bool { return s.State == tswriter.StateSpilling })
	time.Sleep(time.Until(downAt.Add(60 * time.Second)))
	up()
	t.Logf("database started after %.0f s", time.Since(downAt).Seconds())
	time.Sleep(5 * time.Second)
	stop()
	<-done
	total := int(sent.Load())
	waitUntil(t, 60*time.Second, "every row", func() bool { n, _ := h.rows(); return n >= total })
	time.Sleep(time.Second)
	n, distinct := h.rows()
	if n != total || distinct != total {
		t.Fatalf("sent %d, stored %d (%d distinct)", total, n, distinct)
	}
	if g := h.count(`SELECT count(*) FROM writer_gaps`); g != 0 {
		t.Fatalf("%d gaps recorded with nothing lost", g)
	}
	s := h.lastStatus(15*time.Second, func(s status) bool {
		return s.State == tswriter.StateOK && len(s.Tables) > 0 && s.Tables[0].QueueRows == 0 && s.Counters[tswriter.CounterRowsWritten] == float64(total)
	})
	if s.Counters[tswriter.CounterSpills] < 1 || s.Counters[tswriter.CounterWriteFailed] < 1 {
		t.Fatalf("status %+v", s)
	}
	h.stdout.waitFor(t, time.Second, "telemetry writes resumed", nil)
	t.Logf("recovery: sent %d rows, stored %d, deduplicated %.0f, spills %.0f, failed writes %.0f; final state %s",
		total, n, s.Counters[tswriter.CounterRowsDeduplicated], s.Counters[tswriter.CounterSpills], s.Counters[tswriter.CounterWriteFailed], s.State)
}

// E-02: started with the database absent, the writer says so, keeps the
// rows in JetStream, and writes them once the database is there.
func TestIntegrationStartsWithTheDatabaseDownAndSaysSo(t *testing.T) {
	h := newHarness(t)
	p := newProxy(t, h.target())
	p.down()
	h.start(map[string]string{"TS_URL": h.via(p)}, tswriter.Options{})
	h.stdout.waitFor(t, 10*time.Second, "telemetry database unavailable at start: writes are retried and rows wait in JetStream", nil)
	h.put(h.batch(4))
	h.lastStatus(10*time.Second, func(s status) bool { return s.State == tswriter.StateWriteFailing })
	p.up()
	h.stdout.waitFor(t, 10*time.Second, "telemetry database connected", nil)
	waitUntil(t, 20*time.Second, "rows", func() bool { n, _ := h.rows(); return n == 4 })
	h.lastStatus(10*time.Second, func(s status) bool {
		return s.State == tswriter.StateOK && s.Counters[tswriter.CounterRowsWritten] == 4
	})
}

// D7: a schema older than the build stops the writer, naming both
// versions; the twin, the newest schema, is every other test here.
func TestIntegrationOlderSchemaStopsTheWriter(t *testing.T) {
	h := newHarness(t)
	if err := migrate.DownTo(context.Background(), h.db, migrate.Timeseries, 4); err != nil {
		t.Fatal(err)
	}
	m := map[string]string{"NATS_URL": natsURL(t), "TS_URL": h.dbURL, "ADMIN_ADDR": "127.0.0.1:0", "SHUTDOWN_TIMEOUT_S": "5"}
	out := &lines{}
	code := proc.Main(context.Background(), specWith(&config.TSDBWriter{}, tswriter.Options{}), nil, out, io.Discard,
		func(k string) (string, bool) { v, ok := m[k]; return v, ok })
	latest, err := migrate.Latest(migrate.Timeseries)
	if err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("timeseries schema is at version 4, this build needs %d", latest); code != proc.ExitFailed || !strings.Contains(out.tail(10), want) {
		t.Fatalf("exit %d:\n%s", code, out.tail(10))
	}
}

// The retention check in the process (E-01): clean on a clean table,
// an error line after a backdated insert.
func TestIntegrationRetentionCheckCleanThenViolated(t *testing.T) {
	h := newHarness(t)
	for _, q := range []string{
		`CREATE TABLE wp9_dp_probe (rx_ts timestamptz NOT NULL, flight text NOT NULL)`,
		`SELECT create_hypertable('wp9_dp_probe', by_range('rx_ts'))`,
		`SELECT authority_hypertable_policies('wp9_dp_probe', 'flight', 'rx_ts DESC', NULL, INTERVAL '24 hours')`,
	} {
		if _, err := h.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	// The policy's first run would drop the backdated row below if it
	// came after it (storetest.PauseRetention).
	storetest.PauseRetention(t, h.db, "wp9_dp_probe")
	h.start(map[string]string{"TSDB_WRITER_RETENTION_CHECK_S": "1"}, tswriter.Options{
		RetentionChecks: []tswriter.RetentionCheck{{Table: "wp9_dp_probe", Column: "rx_ts", MaxAge: 24 * time.Hour}},
	})
	h.stdout.waitFor(t, 10*time.Second, "retention check: nothing older than the retention period", nil)
	if len(h.stdout.all("retention violated: rows older than the table's retention period remain")) != 0 {
		t.Fatal("violated on a clean table")
	}
	if _, err := h.db.Exec(`INSERT INTO wp9_dp_probe VALUES (now() - interval '25 hours', 'f1')`); err != nil {
		t.Fatal(err)
	}
	v := h.stdout.waitFor(t, 10*time.Second, "retention violated: rows older than the table's retention period remain", nil)
	if v["level"] != "ERROR" || v["table"] != "wp9_dp_probe" {
		t.Fatalf("%v", v)
	}
	h.lastStatus(5*time.Second, func(s status) bool { return s.Counters[tswriter.CounterRetentionViolations] >= 1 })
}

// Load smoke (spec 05 §7): 3000 rows/s for 60 s, 50 messages of 60 rows
// a second. Every row is stored and the writer's queue stays under 10 s
// throughout (sampled on the 1 s status line).
func TestIntegrationLoadSmoke(t *testing.T) {
	h := newHarness(t)
	h.start(nil, tswriter.Options{})
	const seconds, perSecond, rowsPerMsg = 60, 50, 60
	start := time.Now()
	for s := range seconds {
		for range perSecond {
			h.put(h.batch(rowsPerMsg))
		}
		time.Sleep(time.Until(start.Add(time.Duration(s+1) * time.Second)))
	}
	sendFor := time.Since(start)
	total := seconds * perSecond * rowsPerMsg
	waitUntil(t, 60*time.Second, "every row", func() bool { n, _ := h.rows(); return n >= total })
	drained := time.Since(start)
	var maxAge float64
	var maxRows int
	var spills float64
	for _, m := range h.stdout.all("status") {
		s := parseStatus(m)
		for _, tb := range s.Tables {
			maxAge = max(maxAge, tb.QueueAgeS)
			maxRows = max(maxRows, tb.QueueRows)
		}
		spills = max(spills, s.Counters[tswriter.CounterSpills])
	}
	n, distinct := h.rows()
	t.Logf("load smoke: sent %d rows in %.1f s (%.0f rows/s), all stored after %.1f s; stored %d (%d distinct); queue max %d rows, max age %.2f s; spills %.0f",
		total, sendFor.Seconds(), float64(total)/sendFor.Seconds(), drained.Seconds(), n, distinct, maxRows, maxAge, spills)
	if n != total || distinct != total || maxAge >= 10 || spills != 0 {
		t.Fatalf("stored %d/%d distinct %d, max queue age %.2f s, spills %.0f", n, total, distinct, maxAge, spills)
	}
}
