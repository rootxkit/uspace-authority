package zonesvc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// Counters of a ProjectionReader.
const (
	CounterReaderLoaded     = "zones_projection_loaded"      // projection reads applied
	CounterReaderReadFailed = "zones_projection_read_failed" // a read failed; the index held is kept
	CounterNotJudged        = "zones_not_judged"             // a zone in force that could not be built for judgement (named on the status line)
)

// DefaultReaderRefresh is the readers' re-read period (60 s, the brief;
// a publication is pushed on zones.v1.changed at once).
const DefaultReaderRefresh = 60 * time.Second

// ProjectedRow is one row read from proj_zones.
type ProjectedRow struct {
	Dataset      Dataset
	Identifier   string
	ZoneVersion  int
	Feature      json.RawMessage
	ValidFrom    time.Time
	ValidTo      time.Time
	ZonesVersion int64
	ProjectedAt  time.Time
}

// ProjectionSource reads the whole projection.
type ProjectionSource interface {
	LoadZones(ctx context.Context) ([]ProjectedRow, error)
}

// TSSource reads proj_zones as authority_ts_reader.
type TSSource struct {
	R *ts.Reader
}

// LoadZones reads every projected row in one read-only transaction.
func (s TSSource) LoadZones(ctx context.Context) ([]ProjectedRow, error) {
	var out []ProjectedRow
	err := s.R.ReadTx(ctx, func(q *reader.Queries) error {
		rows, err := q.ProjectedZones(ctx)
		if err != nil {
			return err
		}
		out = make([]ProjectedRow, 0, len(rows))
		for i := range rows {
			r := &rows[i]
			out = append(out, ProjectedRow{
				Dataset: Dataset(r.Dataset), Identifier: r.Identifier, ZoneVersion: int(r.ZoneVersion), Feature: r.Feature,
				ValidFrom: r.ValidFrom, ValidTo: r.ValidTo, ZonesVersion: r.ZonesVersion, ProjectedAt: r.ProjectedAt,
			})
		}
		return nil
	})
	return out, err
}

// built is one judgement view of the rows at an instant.
type built struct {
	index        *zones.Index
	zones        []*zones.Zone
	notJudged    []string
	needsTerrain []string
	needsGeoid   []string
	next         time.Time // the next instant a period starts or ends; zero when none
}

// selectInForce keeps, per dataset and identifier, the newest version
// whose period holds at (both ends included).
func selectInForce(rows []ProjectedRow, at time.Time) []ProjectedRow {
	best := map[string]int{}
	var out []ProjectedRow
	for i := range rows {
		r := &rows[i]
		if at.Before(r.ValidFrom) || at.After(r.ValidTo) {
			continue
		}
		k := string(r.Dataset) + "/" + r.Identifier
		if i, ok := best[k]; ok {
			if out[i].ZoneVersion < r.ZoneVersion {
				out[i] = *r
			}
			continue
		}
		best[k] = len(out)
		out = append(out, *r)
	}
	return out
}

// nextBoundary is the first instant after at when a row's period starts
// or ends (the end is included, so the instant after it).
func nextBoundary(rows []ProjectedRow, at time.Time) time.Time {
	var next time.Time
	consider := func(t time.Time) {
		if t.After(at) && (next.IsZero() || t.Before(next)) {
			next = t
		}
	}
	for i := range rows {
		r := &rows[i]
		consider(r.ValidFrom)
		consider(r.ValidTo.Add(time.Nanosecond))
	}
	return next
}

// build turns the rows in force at at into a zones.Index through
// ed318.Parse and ed318.ToZones (the judgement view is uspace-core's).
// A row that cannot be built (a daylight schedule while no daylight
// source is wired, a feature that does not parse) is left out and named
// in notJudged; the rest are indexed.
func build(rows []ProjectedRow, at time.Time, dl ed318.Daylight) built {
	b := built{next: nextBoundary(rows, at)}
	inForce := selectInForce(rows, at)
	for i := range inForce {
		r := &inForce[i]
		name := fmt.Sprintf("%s/%s@%d", r.Dataset, r.Identifier, r.ZoneVersion)
		fc, probs := ed318.Parse(wrapFeature(r.Feature), ed318.Limits{})
		if probs != nil {
			b.notJudged = append(b.notJudged, name+": "+probs.Error())
			continue
		}
		zs, err := ed318.ToZones(fc, dl)
		if err != nil {
			b.notJudged = append(b.notJudged, name+": "+err.Error())
			continue
		}
		for _, z := range zs {
			if z.NeedsTerrain() {
				b.needsTerrain = append(b.needsTerrain, z.Country+"/"+z.Identifier)
			}
			if z.NeedsGeoid() {
				b.needsGeoid = append(b.needsGeoid, z.Country+"/"+z.Identifier)
			}
		}
		b.zones = append(b.zones, zs...)
	}
	sort.Strings(b.notJudged)
	sort.Strings(b.needsTerrain)
	sort.Strings(b.needsGeoid)
	b.index = zones.NewIndex(b.zones)
	return b
}

// ProjectionReader holds the zones.Index a detector judges with (G-08):
// it re-reads the projection every period and when told a new version
// exists, rebuilds the index at the instant a period starts or ends,
// replaces the index whole on a good read, and keeps the one it holds
// when a read fails. Before the first good read Index is nil.
type ProjectionReader struct {
	Source   ProjectionSource
	Daylight ed318.Daylight
	Counters *core.Counters
	Logger   *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	mu       sync.RWMutex
	rows     []ProjectedRow
	view     *built
	loadedAt time.Time
	version  int64

	notifyOnce sync.Once
	notify     chan struct{}
}

func (r *ProjectionReader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r *ProjectionReader) daylight() ed318.Daylight {
	if r.Daylight == nil {
		return NoDaylight{}
	}
	return r.Daylight
}

func (r *ProjectionReader) notifications() chan struct{} {
	r.notifyOnce.Do(func() { r.notify = make(chan struct{}, 1) })
	return r.notify
}

// Notify says a newer zones version exists (zones.v1.changed); Run
// re-reads at once.
func (r *ProjectionReader) Notify() {
	select {
	case r.notifications() <- struct{}{}:
	default:
	}
}

// Refresh reads the projection once. On success the index is rebuilt
// from it; on failure the index held stays and the failure is counted
// and returned.
func (r *ProjectionReader) Refresh(ctx context.Context) error {
	rows, err := r.Source.LoadZones(ctx)
	if err != nil {
		if r.Counters != nil {
			r.Counters.Inc(CounterReaderReadFailed)
		}
		return err
	}
	var version int64
	for i := range rows {
		version = max(version, rows[i].ZonesVersion)
	}
	now := r.now()
	b := build(rows, now, r.daylight())
	r.mu.Lock()
	r.rows, r.view, r.loadedAt, r.version = rows, &b, now, version
	r.mu.Unlock()
	if r.Counters != nil {
		r.Counters.Inc(CounterReaderLoaded)
		if len(b.notJudged) > 0 {
			r.Counters.Add(CounterNotJudged, uint64(len(b.notJudged)))
		}
	}
	return nil
}

// rebuild rebuilds the index from the rows held, at now (a period
// started or ended).
func (r *ProjectionReader) rebuild() {
	r.mu.RLock()
	rows := r.rows
	r.mu.RUnlock()
	b := build(rows, r.now(), r.daylight())
	r.mu.Lock()
	r.view = &b
	r.mu.Unlock()
}

// next is the instant of the next period boundary, zero when none.
func (r *ProjectionReader) next() time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.view == nil {
		return time.Time{}
	}
	return r.view.next
}

// Run refreshes at once, then every period, on Notify, and rebuilds at
// every period boundary, until ctx ends. A failed refresh is logged and
// the index held is kept.
func (r *ProjectionReader) Run(ctx context.Context, every time.Duration) {
	logger := r.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	refresh := func() {
		if err := r.Refresh(ctx); err != nil && ctx.Err() == nil {
			logging.Error(ctx, logger, "zones projection not read; the index held is kept", err,
				slog.Int64("zones_version", r.Version()))
		}
	}
	refresh()
	t := time.NewTicker(every)
	defer t.Stop()
	boundary := time.NewTimer(time.Hour)
	defer boundary.Stop()
	arm := func() {
		boundary.Stop()
		if n := r.next(); !n.IsZero() {
			boundary.Reset(max(n.Sub(r.now()), time.Millisecond))
		}
	}
	arm()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		case <-r.notifications():
			refresh()
		case <-boundary.C:
			r.rebuild()
		}
		arm()
	}
}

// Follow re-reads the projection whenever zones.v1.changed arrives on nc,
// until ctx ends. Without the subscription the periodic re-read still
// carries every change (G-08), and that is said.
func Follow(ctx context.Context, nc *nats.Conn, r *ProjectionReader, logger *slog.Logger) {
	changed := make(chan *nats.Msg, 1)
	sub, err := nc.ChanSubscribe(bus.SubjectZonesChanged, changed)
	if err != nil {
		logger.Warn("zones.v1.changed not followed; the zones projection is re-read periodically only", slog.String("error", err.Error()))
		return
	}
	defer func() { _ = sub.Unsubscribe() }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-changed:
			r.Notify()
		}
	}
}

// Index is the index to judge with, or nil before the first good read.
func (r *ProjectionReader) Index() *zones.Index {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.view == nil {
		return nil
	}
	return r.view.index
}

// Version is the highest zones version of the rows held.
func (r *ProjectionReader) Version() int64 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.version
}

// Ground lists the zones in force that need terrain (an AGL limit to
// judge) and the geoid (a WGS84 limit), as country/identifier, for the
// ground status line (Z-09; the error-level line is WP-12's).
func (r *ProjectionReader) Ground() (needsTerrain, needsGeoid []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.view == nil {
		return nil, nil
	}
	return r.view.needsTerrain, r.view.needsGeoid
}

// NotJudged names every zone in force that could not be built for
// judgement, with the reason.
func (r *ProjectionReader) NotJudged() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.view == nil {
		return nil
	}
	return r.view.notJudged
}

// StatusAttrs are the reader's status-line attributes (E-09): the age
// of the projection held, its zones and version, the zones that need
// terrain or the geoid, and every zone in force that is not judged;
// projection_loaded false until the first good read.
func (r *ProjectionReader) StatusAttrs() []slog.Attr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.view == nil {
		return []slog.Attr{slog.Bool("zones_projection_loaded", false)}
	}
	return []slog.Attr{
		slog.Bool("zones_projection_loaded", true),
		slog.Float64("projection_age_s", r.now().Sub(r.loadedAt).Seconds()),
		slog.Int("zones", len(r.view.zones)),
		slog.Int64("zones_version", r.version),
		slog.Any("zones_need_terrain", r.view.needsTerrain),
		slog.Any("zones_need_geoid", r.view.needsGeoid),
		slog.Any("zones_not_judged", r.view.notJudged),
	}
}
