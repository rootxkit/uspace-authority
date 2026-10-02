package tswriter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Msg is what a pipeline needs of a delivered TSW message (the
// jetstream.Msg subset, so tests drive a pipeline without a server).
type Msg interface {
	Data() []byte
	Headers() nats.Header
	Metadata() (*jetstream.MsgMetadata, error)
	Ack() error
	Nak() error
	InProgress() error
}

// Hole is a run of stream sequences that are no longer in the stream.
type Hole struct {
	FromSeq, ToSeq uint64
	// Count is how many sequences in [FromSeq, ToSeq] are gone.
	Count uint64
}

// Jump is a step in the stream sequences one consumer was delivered:
// the sequences strictly between After and Before were not delivered to
// it.
type Jump struct {
	After, Before uint64
}

// Source is one table's consumer.
type Source interface {
	// Fetch returns up to n messages, waiting at most wait for the first.
	Fetch(ctx context.Context, n int, wait time.Duration) ([]Msg, error)
	// AckFloor is the stream sequence below which every message of this
	// consumer is acknowledged (0 when none), read once at start.
	AckFloor(ctx context.Context) (uint64, error)
	// Holes reports, per jump, the sequences in it that the stream no
	// longer holds (aged out or deleted); a zero Hole when none.
	Holes(ctx context.Context, jumps []Jump) ([]Hole, error)
	// Cursor reads the stream's last sequence and then the consumer's
	// ack floor and undelivered count, in that order: with NumPending 0,
	// every message of this consumer up to StreamLast was delivered.
	Cursor(ctx context.Context) (Cursor, error)
}

// Cursor is where a consumer stands in its stream.
type Cursor struct {
	StreamLast uint64
	AckFloor   uint64
	NumPending uint64
}

// Store writes parts in one transaction (ts.WriterPool.Write) and reads
// back how far a table was written (ts.WriterPool.Position).
type Store interface {
	Write(ctx context.Context, parts ...ts.Part) ([]ts.Written, error)
	// Position is the highest stream sequence written for table; false
	// when none is recorded.
	Position(ctx context.Context, table, stream string) (uint64, bool, error)
}

// Gap causes this package records (writer_gaps.cause).
const (
	CauseStreamRetention = "stream_retention"
	CauseStreamPurge     = "stream_purge"
	CauseMalformed       = "malformed"
	CauseRejected        = "rejected"
)

// Counter names (E-09): on the status line and /metrics.
const (
	CounterRowsWritten        = "rows_written"
	CounterRowsDeduplicated   = "rows_deduplicated"
	CounterBatches            = "batches"
	CounterSpills             = "spills"
	CounterGaps               = "gaps"
	CounterGapsDeduplicated   = "gaps_deduplicated"
	CounterGapsObserved       = "gaps_observed"
	CounterMessagesMalformed  = "messages_malformed"
	CounterRowsRejected       = "rows_rejected"
	CounterRejectedUnrecorded = "rejected_unrecorded"
	CounterWriteFailed        = "write_failed"
	CounterFetchFailed        = "fetch_failed"
	CounterHoleCheckFailed    = "hole_check_failed"
	CounterAckFailed          = "ack_failed"
	CounterRedelivered        = "redelivered_while_queued"
	CounterPurgesObserved     = "purges_observed"
	CounterPositionFailed     = "position_read_failed"
)

// Pipeline states (the status line's per-table state).
const (
	StateOK           = "ok"
	StateSpilling     = "spilling"
	StateWriteFailing = "write_failing"
)

// Config bounds one pipeline (TSDB_WRITER_*).
type Config struct {
	// BatchMaxRows and BatchMaxWait: a batch is written at this many
	// rows, or when its oldest row has waited this long (≤ 1000, 500 ms).
	BatchMaxRows int
	BatchMaxWait time.Duration
	// QueueMaxRows and QueueMaxAge bound the in-memory queue (10 s of
	// rows): at either the consumer stops pulling and the rows wait in
	// JetStream (spilling).
	QueueMaxRows int
	QueueMaxAge  time.Duration
	// FetchMax is the messages one pull asks for; FetchWait how long it
	// waits for the first.
	FetchMax  int
	FetchWait time.Duration
	// WriteTimeout bounds one transaction.
	WriteTimeout time.Duration
	// RetryMin and RetryMax bound the doubling wait between failed
	// writes.
	RetryMin, RetryMax time.Duration
	// AckWait is the consumer's; a message held longer than half of it
	// is kept from redelivery with InProgress.
	AckWait time.Duration
	// PurgeCheck is how often an idle consumer reads its ack floor to
	// notice a purge of messages it was never delivered (default 10 s).
	PurgeCheck time.Duration
}

// item is one delivered message in the queue.
type item struct {
	msg     Msg
	seq     uint64
	n       int // rows counted into the queue's bound
	rows    [][]any
	gaps    []ts.Gap
	queued  time.Time
	touched time.Time
}

// Decoder turns one message into rows of the pipeline's table and the
// gaps it carries; an error makes the message a malformed gap.
type Decoder func(m Msg, seq uint64) (rows [][]any, gaps []ts.Gap, err error)

// Pipeline is one table: a consumer on tsw.v1.<table>, a bounded queue
// and a batching writer (spec 05 §5). The queue holds whole delivered
// messages; each is acknowledged only after the transaction holding its
// rows (and any gap it carries) commits (B-05), in delivery order.
type Pipeline struct {
	Table    ts.Table
	Decode   Decoder
	Source   Source
	Store    Store
	Config   Config
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Now      func() time.Time

	mu       sync.Mutex
	queue    []*item
	rows     int
	lastSeq  uint64
	spilling bool
	failing  bool
	failedAt time.Time
	wake     chan struct{}
	once     sync.Once
	// lastPurgeCheck and caughtUp belong to the pull loop (idle, take).
	// caughtUp: the last idle check found nothing of this table
	// undelivered, and the loop has been fetching ever since, so none of
	// its messages can have aged out unseen (they would have been
	// delivered within a fetch wait, not after the stream's max age).
	lastPurgeCheck time.Time
	caughtUp       bool
	// startFloor is the ack floor at start, compared once with the
	// written position (checkPosition, the write loop's).
	startFloor      uint64
	started         bool
	positionChecked bool
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Pipeline) init() {
	p.once.Do(func() { p.wake = make(chan struct{}, 1) })
}

func (p *Pipeline) signal() {
	p.init()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// Snapshot is one pipeline on the status line.
type Snapshot struct {
	Table         string  `json:"table"`
	State         string  `json:"state"`
	QueueRows     int     `json:"queue_rows"`
	QueueMessages int     `json:"queue_messages"`
	QueueAgeS     float64 `json:"queue_age_s"`
	LastSeq       uint64  `json:"last_seq"`
}

// Snapshot reports the pipeline now.
func (p *Pipeline) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := Snapshot{Table: p.Table.Name, State: p.stateLocked(), QueueRows: p.rows, QueueMessages: len(p.queue), LastSeq: p.lastSeq}
	if len(p.queue) > 0 {
		s.QueueAgeS = p.now().Sub(p.queue[0].queued).Seconds()
	}
	return s
}

func (p *Pipeline) stateLocked() string {
	switch {
	case p.spilling:
		return StateSpilling
	case p.failing:
		return StateWriteFailing
	}
	return StateOK
}

// fullLocked reports whether the queue is at its bound: QueueMaxRows
// rows, or a message that has waited QueueMaxAge (10 s of rows).
func (p *Pipeline) fullLocked(now time.Time) bool {
	if p.rows >= p.Config.QueueMaxRows {
		return true
	}
	return len(p.queue) > 0 && now.Sub(p.queue[0].queued) >= p.Config.QueueMaxAge
}

// Run pulls and writes until ctx ends; on return every message still
// queued is unacknowledged and is redelivered to the next writer.
func (p *Pipeline) Run(ctx context.Context) {
	p.init()
	var wg sync.WaitGroup
	wg.Go(func() { p.pull(ctx) })
	wg.Go(func() { p.write(ctx) })
	wg.Wait()
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// start reads the consumer's ack floor: the first delivery after a
// restart is compared with it, so a hole opened while the writer was
// down is recorded too. The floor is also kept for the writer's position
// check (checkPosition): a purge while the writer was down moved it past
// messages never written, with no step left to see.
func (p *Pipeline) start(ctx context.Context) bool {
	for ctx.Err() == nil {
		floor, err := p.Source.AckFloor(ctx)
		if err == nil {
			p.mu.Lock()
			p.lastSeq, p.startFloor, p.started = floor, floor, true
			p.mu.Unlock()
			p.lastPurgeCheck = p.now()
			return true
		}
		p.Counters.Inc(CounterFetchFailed)
		p.Limiter.Limited("tsw_start:"+p.Table.Name).Warn("TSW consumer unavailable; rows wait in JetStream",
			slog.String("table", p.Table.Name), slog.String("error", err.Error()))
		sleep(ctx, p.Config.RetryMin)
	}
	return false
}

// checkPosition compares the ack floor the consumer started from with
// the position this table was written to (writer_positions), once,
// before the first batch is written. The floor moves past what the
// writer wrote only by a purge, so a floor beyond the position is a
// purge while the writer was down, recorded as a stream_purge gap. It
// returns false until the check is done; meanwhile the state is
// write_failing and nothing is written.
func (p *Pipeline) checkPosition(ctx context.Context) bool {
	p.mu.Lock()
	started, floor := p.started, p.startFloor
	p.mu.Unlock()
	if !started {
		return false
	}
	pos, known, err := p.Store.Position(ctx, p.Table.Name, bus.StreamTSW)
	if err != nil {
		p.Counters.Inc(CounterPositionFailed)
		p.mu.Lock()
		if !p.failing {
			p.failing, p.failedAt = true, p.now()
		}
		p.mu.Unlock()
		p.Limiter.Limited("tsw_position:"+p.Table.Name).Warn("written position unreadable; nothing is written until it is, so a purge while the writer was down is not missed",
			slog.String("table", p.Table.Name), slog.String("error", err.Error()))
		return false
	}
	if known && floor > pos && !p.recordPurge(ctx, pos, floor) {
		return false
	}
	p.mu.Lock()
	p.failing = false
	p.mu.Unlock()
	return true
}

// recordPurge writes, in one transaction, the stream_purge gap of the
// sequences (after, floor] and the table's position at floor. The
// consumer's ack floor reached floor without this writer being delivered
// those sequences: they were purged (or deleted) from the stream. One
// stream carries every table, so the count is of TSW messages, an upper
// bound for this table. It reports whether the record is durable.
func (p *Pipeline) recordPurge(ctx context.Context, after, floor uint64) bool {
	g := ts.Gap{
		DedupeKey: fmt.Sprintf("tsw:%s:%s:%d-%d", CauseStreamPurge, p.Table.Name, after+1, floor),
		Table:     p.Table.Name, Stream: bus.StreamTSW, FromSeq: after + 1, ToSeq: floor,
		Cause: CauseStreamPurge, Count: int64(floor - after), CountUnit: ts.UnitMessages, At: p.now().UTC(),
		Detail: "the consumer's acknowledgement floor moved past TSW messages never delivered to this table's consumer: the stream was purged; it carries every table, so the count is an upper bound for this one",
	}
	wctx, cancel := context.WithTimeout(ctx, p.Config.WriteTimeout)
	defer cancel()
	written, err := p.Store.Write(wctx, ts.Part{Table: ts.WriterGaps, Rows: [][]any{g.Row()}}, p.positionPart(floor))
	if err != nil {
		p.failed(err)
		return false
	}
	p.Counters.Inc(CounterPurgesObserved)
	if len(written) > 0 {
		p.Counters.Add(CounterGaps, uint64(written[0].Inserted))
		p.Counters.Add(CounterGapsDeduplicated, uint64(written[0].Duplicates))
	}
	p.Logger.Warn("TSW stream purged: messages never delivered to this table were removed; recorded as a gap",
		slog.String("table", p.Table.Name), slog.Uint64("from_seq", g.FromSeq), slog.Uint64("to_seq", g.ToSeq),
		slog.Uint64("messages", floor-after))
	return true
}

// positionPart raises the table's written position to seq.
func (p *Pipeline) positionPart(seq uint64) ts.Part {
	return ts.Part{Table: ts.WriterPositions, Rows: [][]any{ts.PositionRow(p.Table.Name, bus.StreamTSW, seq)}}
}

// idle runs on an empty fetch, at most every PurgeCheck. It records a
// purge when the ack floor has passed the last sequence delivered (a
// purge of messages never delivered, with nothing delivered after it to
// show a step), and when nothing of this table is undelivered it marks
// the consumer caught up and moves the last sequence accounted for to
// the stream's last: the sequences up to there hold nothing of this
// table that was not delivered, so a later step over them, once other
// tables' messages aged out, is not this table's hole (WP-9's false
// stream_retention on a quiet table).
func (p *Pipeline) idle(ctx context.Context) {
	every := p.Config.PurgeCheck
	if every <= 0 {
		every = 10 * time.Second
	}
	now := p.now()
	if now.Sub(p.lastPurgeCheck) < every {
		return
	}
	p.lastPurgeCheck = now
	cur, err := p.Source.Cursor(ctx)
	if err != nil {
		p.caughtUp = false // the next fetch says why
		return
	}
	p.mu.Lock()
	last := p.lastSeq
	p.mu.Unlock()
	if cur.AckFloor > last && !p.recordPurge(ctx, last, cur.AckFloor) {
		p.caughtUp = false
		return
	}
	p.caughtUp = cur.NumPending == 0
	mark := cur.AckFloor
	if p.caughtUp {
		mark = max(mark, cur.StreamLast)
	}
	p.mu.Lock()
	p.lastSeq = max(p.lastSeq, mark)
	p.mu.Unlock()
}

// setSpilling records the transition into or out of spilling.
func (p *Pipeline) setSpilling(on bool) {
	p.mu.Lock()
	was := p.spilling
	p.spilling = on
	rows, msgs := p.rows, len(p.queue)
	p.mu.Unlock()
	switch {
	case on && !was:
		p.Counters.Inc(CounterSpills)
		p.Logger.Warn("writer queue at its bound: not pulling, rows wait in JetStream (spilling)",
			slog.String("table", p.Table.Name), slog.Int("queue_rows", rows), slog.Int("queue_messages", msgs))
	case !on && was:
		p.Logger.Info("writer queue below its bound: pulling again", slog.String("table", p.Table.Name),
			slog.Int("queue_rows", rows))
	}
}

func (p *Pipeline) pull(ctx context.Context) {
	if !p.start(ctx) {
		return
	}
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for ctx.Err() == nil {
		p.mu.Lock()
		full := p.fullLocked(p.now())
		p.mu.Unlock()
		p.setSpilling(full)
		if full {
			p.caughtUp = false
			select {
			case <-ctx.Done():
			case <-tick.C:
			}
			continue
		}
		msgs, err := p.Source.Fetch(ctx, p.Config.FetchMax, p.Config.FetchWait)
		if err != nil {
			p.caughtUp = false
			if ctx.Err() == nil {
				p.Counters.Inc(CounterFetchFailed)
				p.Limiter.Limited("tsw_fetch:"+p.Table.Name).Warn("TSW fetch failed; rows wait in JetStream",
					slog.String("table", p.Table.Name), slog.String("error", err.Error()))
				sleep(ctx, p.Config.RetryMin)
			}
			continue
		}
		if len(msgs) > 0 {
			p.take(ctx, msgs)
		} else {
			p.idle(ctx)
		}
	}
}

// take queues fetched messages in delivery order. A message already
// queued (redelivered while held) replaces its earlier delivery. A step
// in the stream sequences is checked against the stream; the sequences
// it no longer holds are recorded as a stream_retention gap carried by
// the message after the hole, so the record commits with that message's
// rows. When the check itself fails the messages are given back (Nak)
// and nothing advances.
func (p *Pipeline) take(ctx context.Context, msgs []Msg) {
	now := p.now()
	type fresh struct {
		m    Msg
		seq  uint64
		jump int // index into jumps, or -1
	}
	// Caught up until this delivery: a step can hide none of this
	// table's messages (see caughtUp). Until the next idle check, more may
	// be pending.
	wasCaughtUp := p.caughtUp
	p.caughtUp = false
	p.mu.Lock()
	last := p.lastSeq
	before := last
	queued := make(map[uint64]*item, len(p.queue))
	for _, it := range p.queue {
		queued[it.seq] = it
	}
	p.mu.Unlock()
	var news []fresh
	var jumps []Jump
	for _, m := range msgs {
		meta, err := m.Metadata()
		if err != nil {
			// Not a JetStream message: nothing to place it by. It is
			// recorded as malformed with no sequence and acknowledged
			// with that record.
			news = append(news, fresh{m: m, jump: -1})
			continue
		}
		seq := meta.Sequence.Stream
		if it, ok := queued[seq]; ok {
			p.Counters.Inc(CounterRedelivered)
			p.mu.Lock()
			it.msg, it.touched = m, now
			p.mu.Unlock()
			continue
		}
		f := fresh{m: m, seq: seq, jump: -1}
		if seq > last+1 {
			f.jump = len(jumps)
			jumps = append(jumps, Jump{After: last, Before: seq})
		}
		if seq > last {
			last = seq
		}
		news = append(news, f)
	}
	var holes []Hole
	if len(jumps) > 0 {
		// A purge moves the ack floor past sequences never delivered
		// here: those are recorded as stream_purge, and only what lies
		// beyond the floor is checked for retention.
		floor, err := p.Source.AckFloor(ctx)
		if err == nil && floor > before && !p.recordPurge(ctx, before, floor) {
			err = errPurgeNotRecorded
		}
		if err == nil {
			for i := range jumps {
				if jumps[i].After < floor {
					jumps[i].After = min(floor, jumps[i].Before-1)
				}
			}
			if wasCaughtUp {
				holes = make([]Hole, len(jumps))
			} else {
				holes, err = p.Source.Holes(ctx, jumps)
			}
		}
		if err != nil || len(holes) != len(jumps) {
			p.Counters.Inc(CounterHoleCheckFailed)
			p.Limiter.Limited("tsw_holes:"+p.Table.Name).Warn("could not check the TSW stream for a hole; the messages are given back",
				slog.String("table", p.Table.Name), slog.Any("error", err))
			for _, f := range news {
				if err := f.m.Nak(); err != nil {
					p.Counters.Inc(CounterAckFailed)
				}
			}
			sleep(ctx, p.Config.RetryMin)
			return
		}
	}
	items := make([]*item, 0, len(news))
	added := 0
	for _, f := range news {
		it := p.decode(f.m, f.seq, now)
		if f.jump >= 0 {
			if h := holes[f.jump]; h.Count > 0 {
				g := ts.Gap{
					DedupeKey: fmt.Sprintf("tsw:%s:%s:%d-%d", CauseStreamRetention, p.Table.Name, h.FromSeq, h.ToSeq),
					Table:     p.Table.Name, Stream: bus.StreamTSW, FromSeq: h.FromSeq, ToSeq: h.ToSeq,
					Cause: CauseStreamRetention, Count: int64(h.Count), CountUnit: ts.UnitMessages, At: now.UTC(),
					Detail: "TSW messages gone before this table's consumer reached them; the stream carries every table, so the count is an upper bound for this one",
				}
				it.gaps = append(it.gaps, g)
				p.Counters.Inc(CounterGapsObserved)
				p.Logger.Warn("hole in the TSW stream: messages aged out before they were written",
					slog.String("table", p.Table.Name), slog.Uint64("from_seq", h.FromSeq), slog.Uint64("to_seq", h.ToSeq),
					slog.Uint64("messages", h.Count))
			}
		}
		items = append(items, it)
		added += it.n
	}
	p.mu.Lock()
	p.queue = append(p.queue, items...)
	p.rows += added
	if last > p.lastSeq {
		p.lastSeq = last
	}
	p.mu.Unlock()
	p.signal()
}

// decode makes one message an item; a message that cannot be read
// becomes a malformed gap with as much count as can be read.
func (p *Pipeline) decode(m Msg, seq uint64, now time.Time) *item {
	it := &item{msg: m, seq: seq, queued: now, touched: now}
	var rows [][]any
	var gaps []ts.Gap
	err := errNoSequence
	if seq > 0 {
		rows, gaps, err = p.Decode(m, seq)
	}
	if err == nil {
		it.rows, it.gaps, it.n = rows, gaps, len(rows)
		return it
	}
	p.Counters.Inc(CounterMessagesMalformed)
	n, unit := malformedCount(m.Data())
	key := fmt.Sprintf("tsw:%s:%s:%d", CauseMalformed, p.Table.Name, seq)
	if seq == 0 {
		key = fmt.Sprintf("tsw:%s:%s:unsequenced:%d", CauseMalformed, p.Table.Name, now.UnixNano())
	}
	it.gaps = []ts.Gap{{
		DedupeKey: key, Table: p.Table.Name, Stream: bus.StreamTSW, FromSeq: seq, ToSeq: seq,
		Cause: CauseMalformed, Count: n, CountUnit: unit, At: now.UTC(), Detail: truncate(err.Error()),
	}}
	p.Limiter.Limited("tsw_malformed:"+p.Table.Name).Warn("TSW message not readable; recorded as a gap",
		slog.String("table", p.Table.Name), slog.Uint64("stream_seq", seq), slog.String("error", err.Error()))
	return it
}

// errPurgeNotRecorded: a purge was seen and its gap record could not be
// written yet; the messages are given back.
var errPurgeNotRecorded = errors.New("purge gap record not written")

// errNoSequence: a message without JetStream metadata has nothing to
// place it by.
var errNoSequence = errors.New("message without a stream sequence")

// malformedCount is the rows an unreadable message held when that much
// can be read, else one message: a gap never claims nothing was lost.
func malformedCount(data []byte) (int64, string) {
	var partial struct {
		Rows []json.RawMessage `json:"rows"`
	}
	if err := json.Unmarshal(data, &partial); err == nil && len(partial.Rows) > 0 {
		return int64(len(partial.Rows)), ts.UnitRows
	}
	return 1, ts.UnitMessages
}

func truncate(s string) string {
	const maxDetail = 500
	if len(s) > maxDetail {
		return s[:maxDetail]
	}
	return s
}

// ready reports whether a batch is due: BatchMaxRows rows queued, or the
// oldest message has waited BatchMaxWait.
func (p *Pipeline) ready(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.queue) == 0 {
		return false
	}
	return p.rows >= p.Config.BatchMaxRows || now.Sub(p.queue[0].queued) >= p.Config.BatchMaxWait
}

// next takes the batch at the head of the queue: whole messages up to
// BatchMaxRows rows, at least one. The items stay queued until written.
func (p *Pipeline) next() []*item {
	p.mu.Lock()
	defer p.mu.Unlock()
	var batch []*item
	rows := 0
	for _, it := range p.queue {
		if len(batch) > 0 && rows+len(it.rows) > p.Config.BatchMaxRows {
			break
		}
		batch = append(batch, it)
		rows += len(it.rows)
	}
	return batch
}

func (p *Pipeline) write(ctx context.Context) {
	tick := time.NewTicker(p.Config.BatchMaxWait / 5)
	defer tick.Stop()
	retry := p.Config.RetryMin
	for ctx.Err() == nil {
		if !p.positionChecked {
			if !p.checkPosition(ctx) {
				p.keepAlive()
				sleep(ctx, retry)
				retry = min(2*retry, p.Config.RetryMax)
				continue
			}
			p.positionChecked = true
			retry = p.Config.RetryMin
		}
		if !p.ready(p.now()) {
			select {
			case <-ctx.Done():
				return
			case <-p.wake:
			case <-tick.C:
			}
			continue
		}
		batch := p.next()
		err := p.writeBatch(ctx, batch)
		if err == nil {
			retry = p.Config.RetryMin
			p.done(batch)
			continue
		}
		if ctx.Err() != nil {
			return
		}
		p.failed(err)
		p.keepAlive()
		sleep(ctx, retry)
		retry = min(2*retry, p.Config.RetryMax)
	}
}

// parts are a batch's rows and gaps as one transaction.
func (p *Pipeline) parts(batch []*item) []ts.Part {
	var rows, gaps [][]any
	for _, it := range batch {
		rows = append(rows, it.rows...)
		for i := range it.gaps {
			gaps = append(gaps, it.gaps[i].Row())
		}
	}
	var top uint64
	for _, it := range batch {
		top = max(top, it.seq)
	}
	var out []ts.Part
	if p.Table.Name == ts.WriterGaps.Name {
		out = []ts.Part{{Table: ts.WriterGaps, Rows: append(rows, gaps...)}}
	} else {
		out = []ts.Part{{Table: p.Table, Rows: rows}, {Table: ts.WriterGaps, Rows: gaps}}
	}
	if top > 0 {
		// The position commits with the rows it covers (writer_positions).
		out = append(out, p.positionPart(top))
	}
	return out
}

func (p *Pipeline) store(ctx context.Context, batch []*item) ([]ts.Written, error) {
	wctx, cancel := context.WithTimeout(ctx, p.Config.WriteTimeout)
	defer cancel()
	return p.Store.Write(wctx, p.parts(batch)...)
}

// writeBatch writes batch in one transaction. When the database refuses
// the data itself, each message is written alone, and a message refused
// alone is replaced by a rejected gap carrying its count, so one bad row
// never holds back the rest and is never dropped unrecorded.
func (p *Pipeline) writeBatch(ctx context.Context, batch []*item) error {
	written, err := p.store(ctx, batch)
	if err == nil {
		p.count(written)
		return nil
	}
	if !ts.IsDataError(err) {
		return err
	}
	for _, it := range batch {
		w, err := p.store(ctx, []*item{it})
		if err == nil {
			p.count(w)
			continue
		}
		if !ts.IsDataError(err) {
			return err
		}
		p.reject(ctx, it, err)
	}
	return nil
}

// reject replaces one refused message by a rejected gap.
func (p *Pipeline) reject(ctx context.Context, it *item, cause error) {
	n := int64(len(it.rows))
	unit := ts.UnitRows
	if n == 0 {
		n, unit = 1, ts.UnitMessages
	}
	p.Counters.Add(CounterRowsRejected, uint64(len(it.rows)))
	p.Logger.Error("the database refused a TSW message's rows; recorded as a gap",
		slog.String("table", p.Table.Name), slog.Uint64("stream_seq", it.seq), slog.String("error", cause.Error()))
	it.rows = nil
	it.gaps = []ts.Gap{{
		DedupeKey: fmt.Sprintf("tsw:%s:%s:%d", CauseRejected, p.Table.Name, it.seq), Table: p.Table.Name,
		Stream: bus.StreamTSW, FromSeq: it.seq, ToSeq: it.seq, Cause: CauseRejected, Count: n, CountUnit: unit,
		At: p.now().UTC(), Detail: truncate(cause.Error()),
	}}
	w, err := p.store(ctx, []*item{it})
	if err != nil {
		// Even the record is refused: counted and logged at error level,
		// the message acknowledged so it does not block the table.
		p.Counters.Inc(CounterRejectedUnrecorded)
		p.Logger.Error("a rejected message's gap record was refused too; counted as rejected_unrecorded",
			slog.String("table", p.Table.Name), slog.Uint64("stream_seq", it.seq), slog.String("error", err.Error()))
		it.gaps = nil
		return
	}
	p.count(w)
}

// count adds a committed write to the counters.
func (p *Pipeline) count(written []ts.Written) {
	parts := p.parts(nil)
	for i, w := range written {
		if i >= len(parts) {
			break
		}
		if parts[i].Table.Name == ts.WriterGaps.Name {
			p.Counters.Add(CounterGaps, uint64(w.Inserted))
			p.Counters.Add(CounterGapsDeduplicated, uint64(w.Duplicates))
			continue
		}
		p.Counters.Add(CounterRowsWritten, uint64(w.Inserted))
		p.Counters.Add(CounterRowsDeduplicated, uint64(w.Duplicates))
	}
}

// done acknowledges a committed batch in delivery order and removes it
// from the queue.
func (p *Pipeline) done(batch []*item) {
	p.Counters.Inc(CounterBatches)
	n := 0
	msgs := make([]Msg, len(batch))
	p.mu.Lock()
	for i, it := range batch {
		// take may have swapped in a newer delivery of the message.
		msgs[i] = it.msg
		n += it.n
	}
	p.mu.Unlock()
	for _, m := range msgs {
		if err := m.Ack(); err != nil {
			// Stored; a redelivery writes nothing twice (dedupe key).
			p.Counters.Inc(CounterAckFailed)
		}
	}
	p.mu.Lock()
	p.queue = p.queue[len(batch):]
	p.rows -= n
	if p.rows < 0 {
		p.rows = 0
	}
	recovered := p.failing
	failedFor := p.now().Sub(p.failedAt)
	p.failing = false
	p.mu.Unlock()
	if recovered {
		p.Logger.Info("telemetry writes resumed", slog.String("table", p.Table.Name),
			slog.Float64("failed_for_s", failedFor.Seconds()))
	}
}

func (p *Pipeline) failed(err error) {
	p.Counters.Inc(CounterWriteFailed)
	p.mu.Lock()
	if !p.failing {
		p.failing, p.failedAt = true, p.now()
	}
	rows := p.rows
	p.mu.Unlock()
	p.Limiter.Limited("tsw_write:"+p.Table.Name).Warn("telemetry write failed; the batch is retried and nothing is acknowledged",
		slog.String("table", p.Table.Name), slog.Int("queue_rows", rows), slog.String("error", err.Error()))
}

// keepAlive keeps held messages from redelivery while they wait.
func (p *Pipeline) keepAlive() {
	now := p.now()
	p.mu.Lock()
	var due []Msg
	for _, it := range p.queue {
		if now.Sub(it.touched) >= p.Config.AckWait/2 {
			due = append(due, it.msg)
			it.touched = now
		}
	}
	p.mu.Unlock()
	for _, m := range due {
		if err := m.InProgress(); err != nil {
			p.Counters.Inc(CounterAckFailed)
		}
	}
}

// ErrNoRows is a rows message without rows.
var ErrNoRows = errors.New("rows message has no rows")

// RowsDecoder decodes a tsw.v1.<table> message for t.
func RowsDecoder(t ts.Table) Decoder {
	return func(m Msg, _ uint64) ([][]any, []ts.Gap, error) {
		var in ts.RowsMessageIn
		if err := json.Unmarshal(m.Data(), &in); err != nil {
			return nil, nil, &core.FieldError{Field: "message", Reason: "not a rows message"}
		}
		if in.Table != t.Name {
			return nil, nil, core.Fieldf("table", "%q on the subject of %s", in.Table, t.Name)
		}
		if len(in.Rows) == 0 {
			return nil, nil, ErrNoRows
		}
		rows := make([][]any, 0, len(in.Rows))
		for i, raw := range in.Rows {
			r, err := t.DecodeRow(raw)
			if err != nil {
				return nil, nil, fmt.Errorf("rows[%d]: %w", i, err)
			}
			rows = append(rows, r)
		}
		return rows, nil, nil
	}
}

// GapsDecoder decodes a tsw.v1.writer_gaps message: a producer's gap
// record. Its dedupe key is the message id when the record names stream
// sequences (a retried publish is one hole), and otherwise the TSW
// sequence of the message (two unsequenced records are two holes).
func GapsDecoder(m Msg, seq uint64) ([][]any, []ts.Gap, error) {
	var in ts.GapMessage
	if err := json.Unmarshal(m.Data(), &in); err != nil {
		return nil, nil, &core.FieldError{Field: "message", Reason: "not a gap message"}
	}
	g := ts.Gap{
		Table: in.Table, Stream: in.Stream, FromSeq: in.FromSeq, ToSeq: in.ToSeq, Cause: in.Cause, Count: in.Count,
		CountUnit: in.CountUnit, At: in.At, ReceiverID: in.ReceiverID, Detail: in.Detail,
	}
	if g.Stream == "" {
		g.Stream = ts.DefaultGapStream
	}
	if g.CountUnit == "" {
		g.CountUnit = ts.UnitRows
	}
	id := ""
	if h := m.Headers(); h != nil {
		id = h.Get(jetstream.MsgIDHeader)
	}
	if id != "" && in.FromSeq > 0 {
		g.DedupeKey = "msg:" + id
	} else {
		g.DedupeKey = fmt.Sprintf("tsw:%d", seq)
	}
	if err := g.Validate(); err != nil {
		return nil, nil, err
	}
	return [][]any{g.Row()}, nil, nil
}
