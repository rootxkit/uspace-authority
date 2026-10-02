package violations

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/detectsvc"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/zonesvc"
)

// The scenarios of uspace-lab knowledge/scenarios.md this work package
// owns, through the real stack: tracks published on trk.v1 (core NATS,
// mirrored by TRK), detect's worker reading them through its durable
// consumer and judging with the zones projection read from TimescaleDB
// and internal/ground's DEM, violation/v1 on ALRT, api's consumer
// writing PostgreSQL with an events row per transition. Each raise and
// each clear is read back from the database (INV-02, E-01). The harness
// of internal/ltest (simulated receiver, every process) is WP-25's.

// The zone and the ground: a PROHIBITED square, 0-1500 m AMSL, around
// (41.50, 44.60); internal/ground's synthetic tile N41E044 is 422 m at
// (41.50, 44.50), a sample point.
const (
	e2eZoneLat, e2eZoneLon = 41.50, 44.60
	e2eOutLat              = 41.52
	e2eGroundLat           = 41.50
	e2eGroundLon           = 44.50
)

func e2eFeature() string {
	d := 0.002
	ring := fmt.Sprintf(`[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]]`,
		e2eZoneLon-d, e2eZoneLat-d, e2eZoneLon+d, e2eZoneLat-d, e2eZoneLon+d, e2eZoneLat+d, e2eZoneLon-d, e2eZoneLat+d, e2eZoneLon-d, e2eZoneLat-d)
	return fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":%s,"layer":{"lower":0,"lowerReference":"AMSL","upper":1500,"upperReference":"AMSL","uom":"m"}},"properties":{"identifier":"SC7","country":"GEO","name":[{"text":"SC-07 zone","lang":"en-GB"}],"type":"PROHIBITED","variant":"COMMON","reason":["SENSITIVE"],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]}}`, ring)
}

type stack struct {
	t    *testing.T
	nc   bus.Publisher
	pg   *sql.DB
	srcF *sources.Follower
}

func newStack(t *testing.T) *stack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bp, err := bus.OpenProcess(ctx, bustest.URL(t), config.Bus{BusTRKStorage: "file", SourceControlBucket: "source_control",
		SourceControlMaxValueBytes: 262144, NATSStartAttempts: 1, NATSStartBackoffMS: 10, NATSTimeoutMS: 2000}, "test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bp.Close)

	// The zones projection, as api's projector leaves it.
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	tsAdmin := storetest.Open(t, tsURL)
	if _, err := tsAdmin.Exec(`INSERT INTO proj_zones (dataset, identifier, zone_version, feature, valid_from, valid_to, type,
		bbox_min_lat_deg, bbox_min_lon_deg, bbox_max_lat_deg, bbox_max_lon_deg, projected_at, zones_version)
		VALUES ('zones', 'SC7', 1, $1, now() - interval '1 hour', now() + interval '1 day', 'PROHIBITED', $2, $3, $4, $5, now(), 1)`,
		e2eFeature(), e2eZoneLat-0.002, e2eZoneLon-0.002, e2eZoneLat+0.002, e2eZoneLon+0.002); err != nil {
		t.Fatal(err)
	}
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: tsURL, ApplicationName: "uspace-authority-test-detect"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rd.Close)
	zr := &zonesvc.ProjectionReader{Source: zonesvc.TSSource{R: rd}, Daylight: ground.Daylight(), Counters: &core.Counters{}}
	rr := &detectsvc.RestrictionReader{Source: detectsvc.TSRestrictions{R: rd}, Daylight: ground.Daylight(), Counters: &core.Counters{}}
	if err := zr.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rr.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	g := ground.New(ground.Options{Dir: filepath.Join("..", "ground", "testdata", "tiles"), GeoidFile: filepath.Join("..", "ground", "testdata", "geoid-constant.pgm")})
	pf := policy.NewFollower(nil)
	pf.Apply(policy.Policy{Version: 1, Thresholds: policy.Defaults(), Active: true})
	srcF := sources.NewFollower()
	shared := &detectsvc.Shared{ZoneReader: zr, Restrictions: rr, PolicyF: pf, SourcesF: srcF, Ground: g}
	if p := shared.Problems(); len(p) != 0 {
		t.Fatalf("the stack does not judge everything: %v", p)
	}

	// api: the relational database and the consumer of ALRT.
	pgURL := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(ctx, store.PoolOptions{URL: pgURL, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	svc := &Service{DB: db, Audit: audit.NewWriter(db), MaxExcerptSamples: 600, WriteTimeout: 10 * time.Second, Counters: &core.Counters{}}
	apiDurable := bustest.Name("api_violations")
	cons := &Consumer{Service: svc, BP: bp, Durable: apiDurable, MaxAckPending: 64, AckWait: 30 * time.Second, FetchMax: 16,
		Timeout: 2 * time.Second, RetryDelay: 100 * time.Millisecond, DeliverPolicy: jetstream.DeliverNewPolicy}
	go cons.Run(ctx)

	// detect: one worker for every cell, ticking every 200 ms.
	worker := detectsvc.NewWorker("all", shared, detectsvc.DefaultSettings(), detectsvc.JSPublisher{JS: bp.JS}, nil, nil)
	workerID := bustest.Name("e2e")
	msgs := make(chan jetstream.Msg, 64)
	sw := make(chan struct{}, 1)
	go detectsvc.Pull(ctx, bp, nil, detectsvc.ConsumerSettings{WorkerID: workerID, MaxAckPending: 256, AckWait: 30 * time.Second,
		FetchMax: 16, Timeout: 2 * time.Second, Retry: 100 * time.Millisecond}, msgs, nil)
	go detectsvc.RunWorker(ctx, worker, msgs, sw, 200*time.Millisecond)
	go detectsvc.FanOut(ctx, srcF, []chan struct{}{sw})

	// Both durables exist before the first track (they start at new
	// messages).
	waitFor(t, 10*time.Second, "consumers", func() bool {
		trk, err1 := bp.JS.Consumer(ctx, bus.StreamTRK, "detect_"+strings.ReplaceAll(workerID, "-", "_")+"_all")
		alrt, err2 := bp.JS.Consumer(ctx, bus.StreamALRT, apiDurable)
		return err1 == nil && err2 == nil && trk != nil && alrt != nil
	})
	return &stack{t: t, nc: bp.NC, pg: storetest.Open(t, pgURL), srcF: srcF}
}

func waitFor(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type flyer struct {
	id, inst string
	ident    core.Identification
}

// send publishes one live sample of f at (lat, lon, alt) now, as
// rid-ingest does.
func (s *stack) send(f flyer, lat, lon, altAMSL float64) {
	s.t.Helper()
	now := time.Now()
	airborne := f3411.Airborne
	m, err := track.New("authority/rid-ingest", core.Times{TS: &now, RxTS: now, CapturedAt: now, Source: core.TimeBroadcast},
		track.Body{TrackID: f.id, Trust: core.TrustBroadcast, Source: track.SourceDirectRID, SourceInstance: f.inst,
			Position: track.Position{Lat: lat, Lng: lon}, AltAMSLM: &altAMSL, AltSource: core.AltGeodetic, Status: &airborne,
			Identification: f.ident})
	if err != nil {
		s.t.Fatal(err)
	}
	if err := track.Publish(s.nc, m); err != nil {
		s.t.Fatal(err)
	}
}

// row is a violation as stored.
type row struct {
	id, kind, track, state string
	reason, dataset        *string
	peak                   *float64
	opened, created        time.Time
	closed                 *time.Time
}

func (s *stack) rows() []row {
	s.t.Helper()
	q, err := s.pg.Query(`SELECT violation_id, kind, track_id, detector_state, clear_reason, terrain_source->>'dataset', peak_value,
		opened_at, created_at, closed_at FROM violations ORDER BY created_at`)
	if err != nil {
		s.t.Fatal(err)
	}
	defer q.Close()
	var out []row
	for q.Next() {
		var r row
		if err := q.Scan(&r.id, &r.kind, &r.track, &r.state, &r.reason, &r.dataset, &r.peak, &r.opened, &r.created, &r.closed); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func (s *stack) find(kind, trackID string, closed bool) *row {
	rows := s.rows()
	for i := range rows {
		if r := &rows[i]; r.kind == kind && r.track == trackID && (r.closed != nil) == closed {
			return r
		}
	}
	return nil
}

func (s *stack) events(id string) []string {
	s.t.Helper()
	q, err := s.pg.Query(`SELECT event_type FROM events WHERE entity_type = 'violation' AND entity_id = $1 ORDER BY id`, id)
	if err != nil {
		s.t.Fatal(err)
	}
	defer q.Close()
	var out []string
	for q.Next() {
		var e string
		if err := q.Scan(&e); err != nil {
			s.t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// fly sends every flyer's sample every 200 ms for d.
func (s *stack) fly(d time.Duration, at func(f flyer) (lat, lon, alt float64), fs ...flyer) {
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		for _, f := range fs {
			lat, lon, alt := at(f)
			s.send(f, lat, lon, alt)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func p99(xs []time.Duration) time.Duration {
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	return xs[(len(xs)*99+99)/100-1]
}

// SC-07, SC-04, SC-08 (steps 2-5) and A-M3: raised and cleared through
// the stack, each transition audited, latency measured.
func TestIntegrationScenariosRaiseAndClearThroughTheStack(t *testing.T) {
	s := newStack(t)
	reg := flyer{id: bustest.Name("REG"), inst: "rx-e2e", ident: core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched,
		Serial: strp("TESTE2E1"), OperatorReg: strp("GEO-TEST-E2E"), Basis: core.BasisAsBroadcast}}
	uni := flyer{id: bustest.Name("UNI"), inst: "rx-e2e", ident: core.Identification{Status: core.IdentUnidentified, Reason: core.ReasonNoSerial,
		Basis: core.BasisAsBroadcast}}
	high := flyer{id: bustest.Name("HIGH"), inst: "rx-e2e", ident: reg.ident}

	// SC-07 and SC-04 entry: two aircraft in the PROHIBITED zone at
	// 500 m AMSL (about 78 m over the ground, under the height limit); a
	// third 178 m over the DEM (600 m AMSL over 422 m).
	entered := time.Now()
	s.fly(2*time.Second, func(f flyer) (float64, float64, float64) {
		if f.id == high.id {
			return e2eGroundLat, e2eGroundLon, 600
		}
		return e2eZoneLat, e2eZoneLon, 500
	}, reg, uni, high)
	waitFor(t, 10*time.Second, "four raises", func() bool {
		return s.find("zone_incursion", reg.id, false) != nil && s.find("zone_incursion", uni.id, false) != nil &&
			s.find("unregistered", uni.id, false) != nil && s.find("height_120m", high.id, false) != nil
	})
	if s.find("unregistered", reg.id, false) != nil {
		t.Fatal("the registered aircraft was raised unregistered")
	}
	var latency []time.Duration
	for _, r := range s.rows() {
		latency = append(latency, r.created.Sub(entered))
	}
	h := s.find("height_120m", high.id, false)
	if h.peak == nil || *h.peak < 177 || *h.peak > 179 || h.dataset == nil || *h.dataset != "COP-DEM GLO-30" {
		t.Fatalf("height violation %+v", h)
	}

	// Exit: out of the zone, down to 500 m (78 m over the ground); all
	// clear resolved after the hysteresis.
	s.fly(5*time.Second, func(f flyer) (float64, float64, float64) {
		if f.id == high.id {
			return e2eGroundLat, e2eGroundLon, 500
		}
		return e2eOutLat, e2eZoneLon, 500
	}, reg, uni, high)
	waitFor(t, 10*time.Second, "four clears", func() bool {
		return s.find("zone_incursion", reg.id, true) != nil && s.find("zone_incursion", uni.id, true) != nil &&
			s.find("unregistered", uni.id, true) != nil && s.find("height_120m", high.id, true) != nil
	})
	for _, r := range s.rows() {
		if r.reason == nil || *r.reason != "resolved" {
			t.Fatalf("%s %s cleared %v, want resolved", r.kind, r.track, r.reason)
		}
		if got := s.events(r.id); !slices.Equal(got, []string{"violation_raised", "violation_cleared"}) {
			t.Fatalf("%s %s events %v", r.kind, r.track, got)
		}
		t.Logf("audited: %s %s %s raised and cleared resolved (events %v)", r.id, r.kind, r.track, s.events(r.id))
	}
	t.Logf("raise latency after the first sample in the zone (n=%d): p99 %v", len(latency), p99(latency))
	if p := p99(latency); p > 2*time.Second {
		t.Fatalf("raise p99 %v over 2 s", p)
	}

	// SC-08 steps 2-5: an aircraft hovering in the zone; Remote ID
	// switched off clears it source_disabled at once; switched on, the
	// next sample raises again.
	hover := flyer{id: bustest.Name("HOVER"), inst: "rx-e2e", ident: reg.ident}
	inZone := func(flyer) (float64, float64, float64) { return e2eZoneLat, e2eZoneLon, 500 }
	s.fly(time.Second, inZone, hover)
	waitFor(t, 10*time.Second, "the hover raise", func() bool { return s.find("zone_incursion", hover.id, false) != nil })
	off := time.Now()
	s.srcF.Apply(sources.Document{Epoch: "e2e", Version: 1, Controls: []sources.Control{{SourceType: sources.TypeDirectRID, Enabled: false,
		Reason: "SC-08", Actor: "admin-1", ChangedAt: off, Version: 1}}})
	waitFor(t, 5*time.Second, "the source_disabled clear", func() bool {
		r := s.find("zone_incursion", hover.id, true)
		return r != nil && r.reason != nil && *r.reason == "source_disabled"
	})
	t.Logf("source_disabled clear stored %v after the switch", time.Since(off))
	s.fly(600*time.Millisecond, inZone, hover)
	if r := s.find("zone_incursion", hover.id, false); r != nil {
		t.Fatalf("a disabled source raised %+v", r)
	}
	on := time.Now()
	s.srcF.Apply(sources.Document{Epoch: "e2e", Version: 2, Controls: []sources.Control{{SourceType: sources.TypeDirectRID, Enabled: true,
		Reason: "SC-08", Actor: "admin-1", ChangedAt: on, Version: 2}}})
	s.fly(time.Second, inZone, hover)
	waitFor(t, 5*time.Second, "the raise after re-enabling", func() bool { return s.find("zone_incursion", hover.id, false) != nil })
	if r := s.find("zone_incursion", hover.id, false); r.created.Sub(on) > 2*time.Second {
		t.Fatalf("re-raised %v after the switch", r.created.Sub(on))
	}
}
