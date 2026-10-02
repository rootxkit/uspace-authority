package detectsvc

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
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

// Counters of the restrictions reader (E-09).
const (
	CounterRestrictionsLoaded     = "restrictions_projection_loaded"      // projection reads applied
	CounterRestrictionsReadFailed = "restrictions_projection_read_failed" // a read failed; the restrictions held are kept
	CounterRestrictionsNotJudged  = "restrictions_not_judged"             // a restriction in force that could not be built for judgement
)

// Restriction states judged (the CISP's CisRestriction.state as WP-6
// projects it): an active restriction, and one whose state this build
// does not know (projected "unknown"), fail-safe. A planned one is not in
// force until the ANSP activates it (a new CIS version, pushed); an ended
// or cancelled one is not in force.
var judgedStates = map[string]bool{"active": true, "unknown": true}

// RestrictionSource reads the restrictions projection.
type RestrictionSource interface {
	LoadRestrictions(ctx context.Context) ([]reader.ProjRestriction, error)
}

// TSRestrictions reads proj_restrictions as authority_ts_reader.
type TSRestrictions struct{ R *ts.Reader }

// LoadRestrictions reads every row in one read-only transaction.
func (s TSRestrictions) LoadRestrictions(ctx context.Context) ([]reader.ProjRestriction, error) {
	var out []reader.ProjRestriction
	err := s.R.ReadTx(ctx, func(q *reader.Queries) error {
		var err error
		out, err = q.ReadRestrictions(ctx)
		return err
	})
	return out, err
}

// RestrictionReader holds the dynamic restrictions in force (WP-6's
// projection of the CIS restrictions dataset) as zones for the monitor
// (Z-12): re-read every period and at once on cis.v1.restrictions, kept
// whole when a read fails (G-08). A restriction in force that cannot be
// built is named in NotJudged, which keeps the status line at error
// level: a restriction that is not judged is never silent.
type RestrictionReader struct {
	Source   RestrictionSource
	Daylight ed318.Daylight
	Counters *core.Counters
	Now      func() time.Time

	mu         sync.RWMutex
	zones      []*zones.Zone
	notJudged  []string
	signature  string
	generation uint64
	loaded     bool
	loadedAt   time.Time
	cisVersion int64

	notifyOnce sync.Once
	notify     chan struct{}
}

func (r *RestrictionReader) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func wrapFeature(raw []byte) []byte {
	b := make([]byte, 0, len(raw)+48)
	b = append(b, `{"type":"FeatureCollection","features":[`...)
	b = append(b, raw...)
	return append(b, "]}"...)
}

// Refresh reads the projection once and rebuilds the restrictions held.
func (r *RestrictionReader) Refresh(ctx context.Context) error {
	rows, err := r.Source.LoadRestrictions(ctx)
	if err != nil {
		r.Counters.Inc(CounterRestrictionsReadFailed)
		return err
	}
	var zs []*zones.Zone
	var notJudged, names []string
	var version int64
	for i := range rows {
		row := &rows[i]
		version = max(version, row.CisVersion)
		if !judgedStates[row.State] {
			continue
		}
		name := fmt.Sprintf("restriction/%s@%d:%s", row.Identifier, row.CisVersion, row.State)
		names = append(names, name)
		fc, probs := ed318.Parse(wrapFeature(row.Feature), ed318.Limits{})
		if probs != nil {
			notJudged = append(notJudged, name+": "+probs.Error())
			continue
		}
		built, err := ed318.ToZones(fc, r.Daylight)
		if err != nil {
			notJudged = append(notJudged, name+": "+err.Error())
			continue
		}
		zs = append(zs, built...)
	}
	sort.Strings(names)
	sort.Strings(notJudged)
	sig := strings.Join(names, "|")
	r.mu.Lock()
	if !r.loaded || sig != r.signature {
		r.generation++
	}
	r.zones, r.notJudged, r.signature, r.loaded, r.loadedAt, r.cisVersion = zs, notJudged, sig, true, r.now(), version
	r.mu.Unlock()
	r.Counters.Inc(CounterRestrictionsLoaded)
	if len(notJudged) > 0 {
		r.Counters.Add(CounterRestrictionsNotJudged, uint64(len(notJudged)))
	}
	return nil
}

// Set is the restrictions held: the zones, the generation (raised when
// another restriction is in force or left out), whether any read
// succeeded, and the restrictions in force that are not judged.
func (r *RestrictionReader) Set() (zs []*zones.Zone, generation uint64, loaded bool, notJudged []string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.zones, r.generation, r.loaded, r.notJudged
}

func (r *RestrictionReader) notifications() chan struct{} {
	r.notifyOnce.Do(func() { r.notify = make(chan struct{}, 1) })
	return r.notify
}

// Notify says a newer restrictions version exists; Run re-reads at once.
func (r *RestrictionReader) Notify() {
	select {
	case r.notifications() <- struct{}{}:
	default:
	}
}

// Run refreshes at once, then every period and on Notify, until ctx
// ends. A failed refresh keeps what is held and is logged.
func (r *RestrictionReader) Run(ctx context.Context, every time.Duration, logger *slog.Logger) {
	if logger == nil {
		logger = logging.Discard()
	}
	refresh := func() {
		if err := r.Refresh(ctx); err != nil && ctx.Err() == nil {
			logging.Error(ctx, logger, "restrictions projection not read; the restrictions held are kept", err)
		}
	}
	refresh()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-r.notifications():
		}
		refresh()
	}
}

// DatasetRestrictions names the restrictions dataset in its CIS cache
// announcement, cis.v1.<dataset> (internal/cisp BusAnnouncer).
const DatasetRestrictions = "restrictions"

// FollowRestrictions re-reads the projection whenever the restrictions
// dataset is announced on nc, until ctx ends (Z-12: a pushed restriction
// is judged within one telemetry tick).
func FollowRestrictions(ctx context.Context, nc *nats.Conn, r *RestrictionReader, logger *slog.Logger) {
	ch := make(chan *nats.Msg, 1)
	subject, err := bus.Subjects.Cis(DatasetRestrictions)
	if err != nil {
		return
	}
	sub, err := nc.ChanSubscribe(subject, ch)
	if err != nil {
		logger.Warn("cis.v1.restrictions not followed; the restrictions projection is re-read periodically only",
			slog.String("error", err.Error()))
		return
	}
	defer func() { _ = sub.Unsubscribe() }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			r.Notify()
		}
	}
}

// StatusAttrs are the reader's status-line attributes.
func (r *RestrictionReader) StatusAttrs() []slog.Attr {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.loaded {
		return []slog.Attr{slog.Bool("restrictions_projection_loaded", false)}
	}
	return []slog.Attr{
		slog.Bool("restrictions_projection_loaded", true),
		slog.Float64("restrictions_projection_age_s", r.now().Sub(r.loadedAt).Seconds()),
		slog.Int("restrictions", len(r.zones)),
		slog.Int64("restrictions_cis_version", r.cisVersion),
		slog.Any("restrictions_not_judged", r.notJudged),
	}
}
