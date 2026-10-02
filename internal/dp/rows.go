package dp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// FlightRow is one ussp_flights row (timeseries 00011): a Service
// Provider's flight as received, with its details when fetched, written
// by tsdb-writer and disposed of within 24 h (CLAUDE.md rule 7, F3411
// NetDpMaxDataRetentionPeriodSeconds). The details are personal data of
// the PII class: they may carry the remote pilot's position (F3411
// operator_location), which only the console realm is shown (WP-13).
type FlightRow struct {
	RxTS            time.Time       `json:"rx_ts"`
	DedupeKey       string          `json:"dedupe_key"`
	USSPID          string          `json:"ussp_id"`
	USSBaseURL      string          `json:"uss_base_url"`
	ISAID           *string         `json:"isa_id"`
	FlightID        string          `json:"flight_id"`
	TrackID         string          `json:"track_id"`
	StateTS         time.Time       `json:"state_ts"`
	ProviderUnknown bool            `json:"provider_unknown"`
	Flight          json.RawMessage `json:"flight"`
	Details         json.RawMessage `json:"details"`
}

// NewFlightRow is the row of one published state.
func NewFlightRow(p *Provider, isaID, flightID, trackID string, rx, stateTS time.Time, flight, details []byte) FlightRow {
	r := FlightRow{
		RxTS: rx.UTC(), DedupeKey: DedupeKey(p.USSID, flightID, stateTS), USSPID: p.USSID, USSBaseURL: p.BaseURL,
		FlightID: flightID, TrackID: trackID, StateTS: stateTS.UTC(), ProviderUnknown: !p.Known,
		Flight: flight, Details: details,
	}
	if isaID != "" {
		r.ISAID = &isaID
	}
	if len(r.Flight) == 0 {
		r.Flight = json.RawMessage("{}")
	}
	if len(r.Details) == 0 {
		r.Details = nil
	}
	return r
}

// Tables of the Display Provider's rows.
const (
	TableTracks      = "tracks"
	TableUSSPFlights = "ussp_flights"
)

// CauseHandOver is the gap cause of rows dp-poller could not hand over.
const CauseHandOver = "dp_handover_failed"

// Counters of the bus sink (E-09).
const (
	CounterRowsHandedOver = "rows_handed_to_writer"
	CounterRowsRetried    = "rows_handover_retried"
	CounterRowsLost       = "rows_lost_handover_failed"
	CounterRowsShed       = "rows_shed_queue_full"
	CounterGapsRecorded   = "gap_records_written"
	CounterGapsLost       = "gap_records_lost"
)

// rowsPerMessage bounds the rows of one TSW message, so a poll of 500
// flights with their details stays under the stream's 1 MiB message
// (bus.MaxPayloadBytes).
const rowsPerMessage = 100

// QueueSize bounds the hand-over queue in poll batches (E-10).
const QueueSize = 1024

// BusSink publishes tracks and identification changes over core NATS
// and hands rows to tsdb-writer (ts.Writer) through a bounded queue
// drained by one worker, so a slow JetStream never holds a poll: each
// message carries a fixed message id (stored once inside the duplicate
// window) and is retried at most Attempts times. Rows that cannot be
// handed over, or that the full queue sheds, are counted, logged at
// error level and recorded as a writer_gaps gap (B-13: a gap is never
// silent).
type BusSink struct {
	NC       bus.Publisher
	Writer   ts.Writer
	Attempts int
	Backoff  time.Duration
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter

	once  sync.Once
	queue chan batch
	mu    sync.Mutex
	seq   uint64
}

type batch struct {
	tracks  []track.Row
	flights []FlightRow
	at      time.Time
}

func (s *BusSink) init() {
	s.once.Do(func() {
		s.queue = make(chan batch, QueueSize)
		if s.Counters == nil {
			s.Counters = &core.Counters{}
		}
		if s.Logger == nil {
			s.Logger = logging.Discard()
		}
		if s.Limiter == nil {
			s.Limiter = logging.NewLimiter(s.Logger, time.Minute, 0, s.Counters)
		}
		if s.Attempts <= 0 {
			s.Attempts = 3
		}
		if s.Backoff <= 0 {
			s.Backoff = 200 * time.Millisecond
		}
	})
}

// Track implements Sink.
func (s *BusSink) Track(m *Message) error { return m.Publish(s.NC) }

// Ident implements Sink.
func (s *BusSink) Ident(c *track.IdentChange) error { return track.PublishIdent(s.NC, c) }

// Rows implements Sink: queued, never blocking a poll.
func (s *BusSink) Rows(tracks []track.Row, flights []FlightRow) {
	s.init()
	select {
	case s.queue <- batch{tracks: tracks, flights: flights, at: time.Now()}:
	default:
		s.Counters.Add(CounterRowsShed, uint64(len(tracks)+len(flights)))
		s.lost(context.Background(), "queue full", len(tracks), len(flights), time.Now())
	}
}

// Depth is the batches waiting.
func (s *BusSink) Depth() int {
	s.init()
	return len(s.queue)
}

// Run drains the queue until ctx ends.
func (s *BusSink) Run(ctx context.Context) {
	s.init()
	for {
		select {
		case <-ctx.Done():
			return
		case b := <-s.queue:
			s.write(ctx, b)
		}
	}
}

func (s *BusSink) nextID(table string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	return fmt.Sprintf("dp:%s:%s:%d", table, bus.NewULID(time.Now()), s.seq)
}

func chunks[R any](rows []R) [][]R {
	var out [][]R
	for len(rows) > rowsPerMessage {
		out = append(out, rows[:rowsPerMessage])
		rows = rows[rowsPerMessage:]
	}
	if len(rows) > 0 {
		out = append(out, rows)
	}
	return out
}

func (s *BusSink) write(ctx context.Context, b batch) {
	lostTracks, lostFlights := 0, 0
	for _, c := range chunks(b.tracks) {
		if !s.enqueue(ctx, TableTracks, c) {
			lostTracks += len(c)
		}
	}
	for _, c := range chunks(b.flights) {
		if !s.enqueue(ctx, TableUSSPFlights, c) {
			lostFlights += len(c)
		}
	}
	handed := len(b.tracks) + len(b.flights) - lostTracks - lostFlights
	s.Counters.Add(CounterRowsHandedOver, uint64(handed))
	if lostTracks+lostFlights > 0 && ctx.Err() == nil {
		s.Counters.Add(CounterRowsLost, uint64(lostTracks+lostFlights))
		s.lost(ctx, "JetStream unavailable", lostTracks, lostFlights, b.at)
	}
}

// enqueue writes one message under a fixed id, at most Attempts times.
func (s *BusSink) enqueue(ctx context.Context, table string, rows any) bool {
	id := s.nextID(table)
	for attempt := 1; attempt <= s.Attempts && ctx.Err() == nil; attempt++ {
		err := s.Writer.Enqueue(ctx, table, rows, id)
		if err == nil {
			return true
		}
		if attempt == s.Attempts {
			s.Limiter.Limited("dp_rows_enqueue").Warn("rows not handed to tsdb-writer", slog.String("table", table),
				slog.String("error", err.Error()))
			break
		}
		s.Counters.Inc(CounterRowsRetried)
		select {
		case <-ctx.Done():
		case <-time.After(s.Backoff * time.Duration(attempt)):
		}
	}
	return false
}

// lost says rows were not handed over and records the gap.
func (s *BusSink) lost(ctx context.Context, why string, tracks, flights int, at time.Time) {
	s.Limiter.Limited("dp_rows_lost").Error("Display Provider rows not handed to tsdb-writer; recorded as a writer gap",
		slog.String("cause", why), slog.Int("tracks", tracks), slog.Int("ussp_flights", flights))
	if s.Writer == nil {
		return
	}
	for _, tn := range []struct {
		table string
		n     int
	}{{TableTracks, tracks}, {TableUSSPFlights, flights}} {
		if tn.n == 0 {
			continue
		}
		g := ts.GapMessage{Table: tn.table, Cause: CauseHandOver, Count: int64(tn.n), At: at.UTC(), CountUnit: ts.UnitRows,
			Detail: why}
		if err := s.Writer.EnqueueGap(context.WithoutCancel(ctx), g, ""); err != nil {
			s.Counters.Inc(CounterGapsLost)
		} else {
			s.Counters.Inc(CounterGapsRecorded)
		}
	}
}
