package picture

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// Counter names of the inputs (E-09).
const (
	CounterProjectionReads       = "projection_reads"
	CounterProjectionReadsFailed = "projection_reads_failed"
	CounterAlertsReplayed        = "alerts_replayed"
	CounterAlertsReplayTruncated = "alerts_replay_truncated"
	CounterAlertsReplayFailed    = "alerts_replay_failed"
	CounterBusLost               = "bus_lost"
	CounterBusDropped            = "bus_messages_dropped"
)

// ProjectionRow is one read of the projection ages and versions
// (reader.PictureProjections): -1 is "never projected".
type ProjectionRow = reader.PictureProjectionsRow

// Projections follows the projection ages and versions of the telemetry
// database (WP-3, WP-5, WP-6): read every interval, ages on the
// database's clock; a failed read keeps the last values, which age on
// from the read on the process's monotonic clock, and says since when
// reads fail (G-08).
type Projections struct {
	Load     func(ctx context.Context) (ProjectionRow, error)
	Counters *core.Counters
	Logger   *slog.Logger

	mu       sync.Mutex
	row      ProjectionRow
	have     bool
	readAt   time.Time
	failing  time.Time
	lastErr  error
	attempts int
}

// Refresh reads once.
func (p *Projections) Refresh(ctx context.Context) {
	row, err := p.Load(ctx)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.attempts++
	if err != nil {
		if p.Counters != nil {
			p.Counters.Inc(CounterProjectionReadsFailed)
		}
		if p.failing.IsZero() {
			p.failing = now
			if p.Logger != nil {
				p.Logger.Warn("projection ages not read; the last values are shown, ageing", slog.String("error", err.Error()))
			}
		}
		p.lastErr = err
		return
	}
	if p.Counters != nil {
		p.Counters.Inc(CounterProjectionReads)
	}
	p.row, p.have, p.readAt, p.failing, p.lastErr = row, true, now, time.Time{}, nil
}

// Run refreshes at once and then every interval until ctx ends.
func (p *Projections) Run(ctx context.Context, every time.Duration) {
	p.Refresh(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.Refresh(ctx)
		}
	}
}

// View is what the status frame carries at now.
func (p *Projections) View(now time.Time) ProjectionView {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := ProjectionView{Read: p.have, FailingSince: p.failing}
	if !p.have {
		if p.attempts == 0 {
			v.FailingSince = time.Time{}
		}
		return v
	}
	since := now.Sub(p.readAt).Seconds()
	if since < 0 {
		since = 0
	}
	if p.row.RegistryAgeS >= 0 {
		v.RegistryAgeS = ptr(round1(p.row.RegistryAgeS + since))
	} else {
		v.RegistryAbsent = true
	}
	if p.row.CisVersion >= 0 {
		v.CISVersion = ptr(strconv.FormatInt(p.row.CisVersion, 10))
		v.CISAgeS = ptr(round1(max(p.row.CisAgeS, 0) + since))
	} else {
		v.CISAbsent = true
	}
	if p.row.ZonesVersion >= 0 {
		v.ZonesVersion = ptr(strconv.FormatInt(p.row.ZonesVersion, 10))
	}
	return v
}

// StatusAttrs puts the ages on the status line.
func (p *Projections) StatusAttrs() []slog.Attr {
	v := p.View(time.Now())
	attrs := []slog.Attr{slog.Bool("projections_read", v.Read)}
	if v.RegistryAgeS != nil {
		attrs = append(attrs, slog.Float64("projection_age_s", *v.RegistryAgeS))
	}
	if v.CISAgeS != nil {
		attrs = append(attrs, slog.Float64("cis_age_s", *v.CISAgeS))
	}
	if !v.FailingSince.IsZero() {
		attrs = append(attrs, slog.String("projections_failing_since", stamp(v.FailingSince)))
	}
	return attrs
}

func round1(x float64) float64 {
	if x < 0 {
		return 0
	}
	return float64(int64(x*10+0.5)) / 10
}

// LazyReader opens the telemetry database read-only on first use and
// again after an open failed, so picture-ws starts with the database
// down and says the projections are unread (B-08, SC-22).
type LazyReader struct {
	Opts store.PoolOptions

	mu sync.Mutex
	r  *ts.Reader
}

// Load implements Projections.Load.
func (l *LazyReader) Load(ctx context.Context) (ProjectionRow, error) {
	l.mu.Lock()
	if l.r == nil {
		r, err := ts.OpenReader(ctx, l.Opts)
		if err != nil {
			l.mu.Unlock()
			return ProjectionRow{}, err
		}
		l.r = r
	}
	r := l.r
	l.mu.Unlock()
	return r.Q.PictureProjections(ctx)
}

// Close closes the pool if one was opened.
func (l *LazyReader) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.r != nil {
		l.r.Close()
		l.r = nil
	}
}

// PolicyOf is the status frame's view of a policy follower: the active
// policy's display thresholds and version, or the documented defaults
// as version 0, said (policy_default).
func PolicyOf(f *policy.Follower) func() PolicyView {
	return func() PolicyView {
		p, ok := f.Current()
		if !ok {
			d := policy.Defaults()
			return PolicyView{Version: "0", StaleAfterS: d.StaleAfterS, LiveMaxAgeS: d.LiveMaxAgeS, CISStaleBoundS: d.CISStaleBoundS, Default: true}
		}
		return PolicyView{Version: PolicyVersion(p.Version), StaleAfterS: p.StaleAfterS, LiveMaxAgeS: p.LiveMaxAgeS, CISStaleBoundS: p.CISStaleBoundS,
			RegNumPattern: p.RegistrationNumberPattern}
	}
}

// BusWatch follows the state of the NATS connection: since when it is
// lost, and what to do when it is lost and when it is back.
type BusWatch struct {
	// Status is the connection's status (nc.Status).
	Status func() nats.Status
	// OnLost and OnBack are called on each transition; OnBack gets the
	// instant the bus was lost.
	OnLost   func(at time.Time)
	OnBack   func(lostAt time.Time)
	Counters *core.Counters
	Logger   *slog.Logger

	mu        sync.Mutex
	connected bool
	since     time.Time
	init      bool
}

// Check reads the status once at now and acts on a transition.
func (w *BusWatch) Check(now time.Time) {
	up := w.Status() == nats.CONNECTED
	w.mu.Lock()
	first := !w.init
	changed := first || up != w.connected
	prev := w.since
	w.init = true
	if changed {
		w.connected = up
		if up {
			w.since = time.Time{}
		} else {
			w.since = now
		}
	}
	w.mu.Unlock()
	if !changed {
		return
	}
	switch {
	case !up:
		if w.Counters != nil {
			w.Counters.Inc(CounterBusLost)
		}
		if w.Logger != nil {
			w.Logger.Error("NATS unavailable: the consoles are told and nothing leaves the picture until it is back")
		}
		if w.OnLost != nil {
			w.OnLost(now)
		}
	case !first:
		if w.Logger != nil {
			w.Logger.Info("NATS back: active violations read back from the moment it was lost", slog.String("lost_at", stamp(prev)))
		}
		if w.OnBack != nil {
			w.OnBack(prev)
		}
	}
}

// Run checks every interval until ctx ends.
func (w *BusWatch) Run(ctx context.Context, every time.Duration) {
	w.Check(time.Now())
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Check(time.Now())
		}
	}
}

// View is the hub's view of the bus.
func (w *BusWatch) View() BusView {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.init {
		return BusView{Connected: true}
	}
	return BusView{Connected: w.connected, Since: w.since}
}

// ReplayAlerts reads ALRT back from since and hands every message to
// offer with the time JetStream stored it, so a console connecting now
// is replayed the active violations at once (C-08) and a clear sent
// while the bus was away is not missed. At most maxMsgs messages are
// read; truncated reports there were more.
func ReplayAlerts(ctx context.Context, js jetstream.JetStream, since time.Time, maxMsgs int,
	offer func(raw []byte, at time.Time),
) (n int, truncated bool, err error) {
	start := since.UTC()
	cons, err := js.OrderedConsumer(ctx, bus.StreamALRT, jetstream.OrderedConsumerConfig{
		FilterSubjects: []string{bus.SubjectAlrtAll}, DeliverPolicy: jetstream.DeliverByStartTimePolicy, OptStartTime: &start,
	})
	if errors.Is(err, jetstream.ErrStreamNotFound) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	for n < maxMsgs {
		batch, err := cons.Fetch(min(256, maxMsgs-n), jetstream.FetchMaxWait(time.Second))
		if err != nil {
			return n, false, err
		}
		got := 0
		var pending uint64
		for msg := range batch.Messages() {
			got++
			n++
			at := time.Now()
			if meta, err := msg.Metadata(); err == nil {
				at, pending = meta.Timestamp, meta.NumPending
			}
			offer(msg.Data(), at)
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) {
			return n, false, err
		}
		if got == 0 || pending == 0 {
			return n, false, nil
		}
	}
	return n, true, nil
}
