package violations

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/detectsvc"
	"github.com/rootxkit/uspace-authority/internal/ground"
	"github.com/rootxkit/uspace-authority/internal/intents"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
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

// WP-26 through the real stack: a U-space airspace in proj_zones
// (TimescaleDB), detect's worker reading trk.v1 through its durable
// consumer, its board reading the fake InterUSS DSS over HTTP
// (POST /dss/v1/operational_intent_references/query with a token for the
// DSS's host granting utm.conformance_monitoring_sa), violation/v1 on
// ALRT, api's consumer writing PostgreSQL with an events row per
// transition. Spec 04 §3.3 (Art. 6(4)): an aircraft inside the airspace
// with an Activated intent raises nothing; its intent ended,
// no_authorisation is raised after the grace and cleared on exit; the
// DSS taken down, the detector is suspended and raises nothing, then
// resumes. Each raise and clear is read back from the database (INV-02,
// E-01, E-02).

const (
	naLat, naLon = 41.60, 44.70
	naOutLat     = 41.65
	naGraceS     = 2
)

func naFeature() string {
	d := 0.01
	ring := fmt.Sprintf(`[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]]`,
		naLon-d, naLat-d, naLon+d, naLat-d, naLon+d, naLat+d, naLon-d, naLat+d, naLon-d, naLat-d)
	return fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":%s,"layer":{"lower":0,"lowerReference":"AMSL","upper":3000,"upperReference":"AMSL","uom":"m"}},"properties":{"identifier":"TSU900","country":"GEO","name":[{"text":"Test U-space airspace","lang":"en-GB"}],"type":"USPACE","variant":"COMMON","reason":["OTHER"],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]}}`, ring)
}

// staticTokens hands every DSS read the same token, recording what was
// asked.
type staticTokens struct {
	mu     sync.Mutex
	scopes []string
}

func (s *staticTokens) Token(_ context.Context, _ string, scopes ...string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scopes = append(s.scopes, scopes...)
	return "test-token", nil
}

type naStack struct {
	*stack
	dss    *fakedss.DSS
	board  *intents.Board
	shared *detectsvc.Shared
	tokens *staticTokens
}

func newNAStack(t *testing.T) *naStack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bp, err := bus.OpenProcess(ctx, bustest.URL(t), config.Bus{BusTRKStorage: "file", SourceControlBucket: "source_control",
		SourceControlMaxValueBytes: 262144, NATSStartAttempts: 1, NATSStartBackoffMS: 10, NATSTimeoutMS: 2000}, "test", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bp.Close)

	// The U-space airspace, as api's projector leaves it (WP-5).
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	tsAdmin := storetest.Open(t, tsURL)
	if _, err := tsAdmin.Exec(`INSERT INTO proj_zones (dataset, identifier, zone_version, feature, valid_from, valid_to, type,
		bbox_min_lat_deg, bbox_min_lon_deg, bbox_max_lat_deg, bbox_max_lon_deg, projected_at, zones_version)
		VALUES ('uspace_airspace', 'TSU900', 1, $1, now() - interval '1 hour', now() + interval '1 day', 'USPACE', $2, $3, $4, $5, now(), 1)`,
		naFeature(), naLat-0.01, naLon-0.01, naLat+0.01, naLon+0.01); err != nil {
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
	th := policy.Defaults()
	th.NoAuthorisationGraceS = naGraceS
	pf.Apply(policy.Policy{Version: 1, Thresholds: th, Active: true})
	srcF := sources.NewFollower()
	shared := &detectsvc.Shared{ZoneReader: zr, Restrictions: rr, PolicyF: pf, SourcesF: srcF, Ground: g}

	// The DSS and the detector's board over it (cmd/detect's wiring with
	// a test token source).
	dss := fakedss.NewDSS()
	t.Cleanup(dss.Close)
	tok := &staticTokens{}
	s := intents.DefaultSettings()
	s.Requery, s.Recheck, s.OutcomeMaxAge = time.Second, 200*time.Millisecond, 3*time.Second
	board := intents.NewBoard(s, &intents.Client{Tokens: tok, DSS: dss.URL()}, func() []*zones.Zone { return shared.Zones().Zones }, nil)
	shared.Intents = board
	go board.Run(ctx, 200*time.Millisecond)

	// api: the relational database and the consumer of ALRT.
	pgURL := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(ctx, store.PoolOptions{URL: pgURL, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	svc := &Service{DB: db, Audit: audit.NewWriter(db), MaxExcerptSamples: 600, WriteTimeout: 10 * time.Second, Counters: &core.Counters{}}
	apiDurable := bustest.Name("api_violations_na")
	cons := &Consumer{Service: svc, BP: bp, Durable: apiDurable, MaxAckPending: 64, AckWait: 30 * time.Second, FetchMax: 16,
		Timeout: 2 * time.Second, RetryDelay: 100 * time.Millisecond, DeliverPolicy: jetstream.DeliverNewPolicy}
	go cons.Run(ctx)

	worker := detectsvc.NewWorker("all", shared, detectsvc.DefaultSettings(), detectsvc.JSPublisher{JS: bp.JS}, nil, nil)
	workerID := bustest.Name("na")
	msgs := make(chan jetstream.Msg, 64)
	sw := make(chan struct{}, 1)
	go detectsvc.Pull(ctx, bp, nil, detectsvc.ConsumerSettings{WorkerID: workerID, MaxAckPending: 256, AckWait: 30 * time.Second,
		FetchMax: 16, Timeout: 2 * time.Second, Retry: 100 * time.Millisecond}, msgs, nil)
	go detectsvc.RunWorker(ctx, worker, msgs, sw, 200*time.Millisecond)
	go detectsvc.FanOut(ctx, srcF, []chan struct{}{sw})

	waitFor(t, 10*time.Second, "consumers", func() bool {
		trk, err1 := bp.JS.Consumer(ctx, bus.StreamTRK, "detect_"+strings.ReplaceAll(workerID, "-", "_")+"_all")
		alrt, err2 := bp.JS.Consumer(ctx, bus.StreamALRT, apiDurable)
		return err1 == nil && err2 == nil && trk != nil && alrt != nil
	})
	waitFor(t, 10*time.Second, "the DSS read", func() bool { st, _ := board.State(); return st == intents.StateAvailable })
	return &naStack{stack: &stack{t: t, nc: bp.NC, pg: storetest.Open(t, pgURL), srcF: srcF}, dss: dss, board: board, shared: shared, tokens: tok}
}

// flying sends a live sample of f every 200 ms at where() until stop is
// called; the samples carry a WGS84 height so the DSS is asked in 4D.
func (s *naStack) flying(f flyer, where func() (lat, lon float64)) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()
		for {
			lat, lon := where()
			now := time.Now()
			airborne := f3411.Airborne
			alt, hae := 500.0, 518.0
			m, err := track.New("authority/rid-ingest", core.Times{TS: &now, RxTS: now, CapturedAt: now, Source: core.TimeBroadcast},
				track.Body{TrackID: f.id, Trust: core.TrustBroadcast, Source: track.SourceDirectRID, SourceInstance: f.inst,
					Position: track.Position{Lat: lat, Lng: lon}, AltAMSLM: &alt, AltWGS84M: &hae, AltSource: core.AltGeodetic, Status: &airborne,
					Identification: f.ident})
			if err == nil {
				_ = track.Publish(s.nc, m)
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}

// position is a settable position for flying.
type position struct {
	mu       sync.Mutex
	lat, lon float64
}

func (p *position) set(lat, lon float64) { p.mu.Lock(); p.lat, p.lon = lat, lon; p.mu.Unlock() }
func (p *position) get() (float64, float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lat, p.lon
}

func activated(id string) (f3548.OperationalIntentReference, f3548.Volume4D) {
	now := time.Now().UTC()
	start, end := now.Add(-time.Hour), now.Add(time.Hour)
	ref := f3548.OperationalIntentReference{Id: id, Manager: "ussp-lab-01", UssBaseUrl: "https://ussp.lab.test", State: f3548.Activated,
		Version: 1, UssAvailability: f3548.Normal, SubscriptionId: "sub-1",
		TimeStart: f3548.Time{Format: f3548.RFC3339, Value: start}, TimeEnd: f3548.Time{Format: f3548.RFC3339, Value: end}}
	r := float32(300)
	ext := f3548.Volume4D{
		TimeStart: &f3548.Time{Format: f3548.RFC3339, Value: start}, TimeEnd: &f3548.Time{Format: f3548.RFC3339, Value: end},
		Volume: f3548.Volume3D{OutlineCircle: &f3548.Circle{Center: &f3548.LatLngPoint{Lat: naLat, Lng: naLon},
			Radius: &f3548.Radius{Units: f3548.RadiusUnitsM, Value: r}},
			AltitudeLower: &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 0},
			AltitudeUpper: &f3548.Altitude{Reference: f3548.W84, Units: f3548.AltitudeUnitsM, Value: 1000}},
	}
	return ref, ext
}

func TestIntegrationNoAuthorisationThroughTheStack(t *testing.T) {
	s := newNAStack(t)
	ident := core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched, Serial: strp("TESTNA01"),
		OperatorReg: strp("GEO-TEST-NA1"), Basis: core.BasisAsBroadcast}
	a := flyer{id: bustest.Name("AUTH"), inst: "rx-na", ident: ident}

	// 1. Authorised: an Activated intent at the aircraft. The board
	// matches it, and past the grace nothing is raised (E-01 absence).
	ref, ext := activated("6f1c1b8e-1d1a-4f6e-9a55-000000000001")
	s.dss.PutIntent(ref, ext)
	pos := &position{lat: naLat, lon: naLon}
	stop := s.flying(a, pos.get)
	defer stop()
	waitFor(t, 15*time.Second, "the aircraft matched", func() bool {
		o, ok := s.board.Outcome(a.id)
		return ok && o.Matched && o.Match.ID == ref.Id && o.VerticalChecked
	})
	matchedAt := time.Now()
	waitFor(t, 15*time.Second, "grace and a margin with the match", func() bool {
		o, ok := s.board.Outcome(a.id)
		return ok && o.Matched && o.CheckedAt.After(matchedAt.Add((naGraceS+1)*time.Second))
	})
	if r := s.find("no_authorisation", a.id, false); r != nil {
		t.Fatalf("an authorised flight raised %+v", r)
	}
	if !slices.Contains(s.tokens.scopes, string(f3548.ScopeConformanceMonitoringForSituationalAwareness)) ||
		slices.ContainsFunc(s.tokens.scopes, func(sc string) bool { return sc != string(f3548.ScopeConformanceMonitoringForSituationalAwareness) }) {
		t.Fatalf("scopes asked %v", s.tokens.scopes)
	}

	// 2. The intent ended (its USSP deleted the reference): no_authorisation
	// after the grace, stored with its raise event.
	ended := time.Now()
	s.dss.DeleteIntent(ref.Id)
	waitFor(t, 20*time.Second, "the no_authorisation raise", func() bool { return s.find("no_authorisation", a.id, false) != nil })
	raised := s.find("no_authorisation", a.id, false)
	if lag := raised.created.Sub(ended); lag < naGraceS*time.Second {
		t.Fatalf("raised %v after the end, inside the %d s grace", lag, naGraceS)
	}
	t.Logf("no_authorisation stored %v after the intent ended (grace %d s)", raised.created.Sub(ended), naGraceS)
	var zoneID, detailWhy string
	if err := s.pg.QueryRow(`SELECT zone_id, detail->'candidates'->0->>'reason' FROM violations WHERE violation_id = $1`, raised.id).
		Scan(&zoneID, &detailWhy); err != nil {
		t.Fatal(err)
	}
	if zoneID != "GEO/TSU900" || (detailWhy != string(intents.ReasonWithdrawn) && detailWhy != string(intents.ReasonNotAtPosition)) {
		t.Fatalf("stored zone %q, reason %q", zoneID, detailWhy)
	}

	// 3. Exit: cleared resolved after the presence's hysteresis.
	pos.set(naOutLat, naLon)
	waitFor(t, 20*time.Second, "the clear on exit", func() bool {
		r := s.find("no_authorisation", a.id, true)
		return r != nil && r.reason != nil && *r.reason == "resolved"
	})
	if got := s.events(raised.id); !slices.Equal(got, []string{"violation_raised", "violation_cleared"}) {
		t.Fatalf("events %v", got)
	}
	t.Logf("audited: %s no_authorisation raised and cleared resolved on exit", raised.id)
	stop()

	// 4. E-02: the DSS taken down. A second aircraft with no intent stays
	// inside past the grace: the detector says it is suspended and
	// raises nothing.
	b := flyer{id: bustest.Name("DOWN"), inst: "rx-na", ident: ident}
	s.dss.SetDown(true)
	waitFor(t, 15*time.Second, "the DSS unavailable", func() bool { st, _ := s.board.State(); return st == intents.StateUnavailable })
	bpos := &position{lat: naLat, lon: naLon}
	stopB := s.flying(b, bpos.get)
	defer stopB()
	waitFor(t, 15*time.Second, "the second aircraft held through the grace and a margin with the DSS down", func() bool {
		st, since := s.board.State()
		return st == intents.StateUnavailable && s.board.Stats().Aircraft >= 1 && time.Since(since) > (naGraceS+2)*time.Second
	})
	if r := s.find("no_authorisation", b.id, false); r != nil {
		t.Fatalf("raised while the DSS was down %+v", r)
	}
	if p := s.shared.Problems(); !slices.ContainsFunc(p, func(x string) bool { return strings.Contains(x, "no_authorisation suspended") }) {
		t.Fatalf("problems while down %v", p)
	}

	// 5. The DSS back: the detector resumes, and the aircraft with no
	// intent is raised after the grace.
	upAt := time.Now()
	s.dss.SetDown(false)
	waitFor(t, 20*time.Second, "the raise after the DSS came back", func() bool { return s.find("no_authorisation", b.id, false) != nil })
	if r := s.find("no_authorisation", b.id, false); r.created.Sub(upAt) < naGraceS*time.Second {
		t.Fatalf("raised %v after resuming, inside the grace", r.created.Sub(upAt))
	}
	if p := s.shared.Problems(); slices.ContainsFunc(p, func(x string) bool { return strings.Contains(x, "no_authorisation") }) {
		t.Fatalf("problems after resuming %v", p)
	}
	bpos.set(naOutLat, naLon)
	waitFor(t, 20*time.Second, "the clear of the second aircraft", func() bool {
		r := s.find("no_authorisation", b.id, true)
		return r != nil && r.reason != nil && *r.reason == "resolved"
	})
	if s.dss.IntentQueries() == 0 {
		t.Fatal("the DSS was never queried")
	}
}
