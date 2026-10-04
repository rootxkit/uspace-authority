package detectsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
	"github.com/rootxkit/uspace-core/f3411"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/intents"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// fakeInputs are a worker's inputs, set by the test.
type fakeInputs struct {
	mu   sync.Mutex
	zs   ZoneSet
	pol  *policy.Policy
	src  *coresources.State
	env  func(core.LatLon) zones.Env
	elev *terrain.Elevation
	// board is the operational intents board (WP-26), nil for none.
	board *intents.Board
}

func (f *fakeInputs) Authorisations() *intents.Board { return f.board }

func (f *fakeInputs) Zones() ZoneSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.zs
}

func (f *fakeInputs) setZones(zs ...*zones.Zone) {
	f.mu.Lock()
	defer f.mu.Unlock()
	versions := map[string]int{}
	for _, z := range zs {
		versions[z.Identifier] = 1
	}
	f.zs = ZoneSet{Zones: zs, Versions: versions, Generation: [2]uint64{f.zs.Generation[0] + 1, 0}, ZonesLoaded: true, RestrictionsLoaded: true}
}

func (f *fakeInputs) Policy() (policy.Policy, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pol == nil {
		return policy.Policy{}, false
	}
	return *f.pol, true
}

func (f *fakeInputs) setPolicy(version int64, mutate func(*policy.Thresholds)) {
	t := policy.Defaults()
	if mutate != nil {
		mutate(&t)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pol = &policy.Policy{Version: version, Thresholds: t, Active: true}
}

func (f *fakeInputs) Sources() (coresources.State, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.src == nil {
		return coresources.State{}, false
	}
	return *f.src, true
}

func (f *fakeInputs) setSources(st coresources.State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.src = &st
}

func (f *fakeInputs) Env(p core.LatLon) zones.Env {
	if f.env == nil {
		return zones.Env{Ground: zones.GroundNotConfigured}
	}
	return f.env(p)
}

func (f *fakeInputs) Elevation(core.LatLon) *terrain.Elevation { return f.elev }

// memPub records every message published, or fails while fail is set.
type memPub struct {
	mu      sync.Mutex
	msgs    []*violation.Message
	fail    bool
	invalid []error
}

var errInjected = errors.New("injected publish failure")

func (p *memPub) PublishViolation(_ context.Context, m *violation.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return errInjected
	}
	if err := violation.Validate(m); err != nil {
		return err
	}
	if _, err := violation.Subject(&m.Body); err != nil {
		return err
	}
	if err := schemaCheck(m); err != nil {
		p.invalid = append(p.invalid, err)
		return err
	}
	p.msgs = append(p.msgs, m)
	return nil
}

func (p *memPub) setFail(v bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fail = v
}

// take returns the messages since the last take, without the
// republications (state updated with no change).
func (p *memPub) take() []*violation.Message {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.msgs
	p.msgs = nil
	return out
}

// transitions keeps raised and cleared messages, and updated ones only
// when keepUpdates.
func transitions(ms []*violation.Message, keepUpdates bool) []*violation.Message {
	var out []*violation.Message
	for _, m := range ms {
		if m.Body.State != violation.StateUpdated || keepUpdates {
			out = append(out, m)
		}
	}
	return out
}

func describe(ms []*violation.Message) string {
	s := ""
	for _, m := range ms {
		r := ""
		if m.Body.ClearReason != nil {
			r = " " + *m.Body.ClearReason
		}
		s += fmt.Sprintf("[%s %s %s %s%s] ", m.Body.State, m.Body.Kind, m.Body.TrackRef, m.Body.Severity, r)
	}
	if s == "" {
		return "none"
	}
	return s
}

// clock is a settable process clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

// rig is a worker with fake inputs, a recording publisher and a clock.
type rig struct {
	t   *testing.T
	in  *fakeInputs
	pub *memPub
	clk *clock
	w   *Worker
}

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func newRig(t *testing.T, mutate func(*Settings)) *rig {
	t.Helper()
	return newRigAt(t, t0, mutate)
}

// newRigAt is newRig with the process clock starting at start.
func newRigAt(t *testing.T, start time.Time, mutate func(*Settings)) *rig {
	t.Helper()
	r := &rig{t: t, in: &fakeInputs{}, pub: &memPub{}, clk: &clock{now: start}}
	r.in.zs = ZoneSet{ZonesLoaded: true, RestrictionsLoaded: true}
	set := DefaultSettings()
	set.Now = r.clk.Now
	if mutate != nil {
		mutate(&set)
	}
	r.w = NewWorker("c3:131:224", r.in, set, r.pub, nil, nil)
	t.Cleanup(func() {
		r.pub.mu.Lock()
		defer r.pub.mu.Unlock()
		for _, err := range r.pub.invalid {
			t.Errorf("a published message breaks schemas/violation/v1.json: %v", err)
		}
	})
	return r
}

// sample is one track sample to send.
type sample struct {
	id      string
	lat     float64
	lon     float64
	altAMSL *float64
	wgs84   *float64
	altSrc  core.AltSource
	press   *float64
	status  *f3411.RIDOperationalStatus
	ident   core.Identification
	source  track.Source
	inst    string
	backlog bool
	trust   core.Trust
}

func f64(v float64) *float64 { return &v }

func registered(serial string) core.Identification {
	return core.Identification{Status: core.IdentRegistered, Reason: core.ReasonMatched, Serial: &serial,
		OperatorReg: strp("GEO-TEST-OP1"), Basis: core.BasisAsBroadcast}
}

func unidentified() core.Identification {
	return core.Identification{Status: core.IdentUnidentified, Reason: core.ReasonNoSerial, Basis: core.BasisAsBroadcast}
}

func airborne() *f3411.RIDOperationalStatus { s := f3411.Airborne; return &s }
func onGround() *f3411.RIDOperationalStatus { s := f3411.Ground; return &s }

// message builds the trk.v1 message of s at t (received at t).
func message(t *testing.T, s sample, at time.Time) *track.Message {
	t.Helper()
	if s.source == "" {
		s.source = track.SourceDirectRID
	}
	if s.inst == "" {
		s.inst = "rx-1"
	}
	if s.trust == "" {
		s.trust = core.TrustBroadcast
	}
	if s.altSrc == "" {
		s.altSrc = core.AltGeodetic
	}
	if s.status == nil {
		s.status = airborne()
	}
	if s.ident.Status == "" {
		s.ident = registered("TEST" + s.id)
	}
	ts := at
	m, err := track.New("authority/rid-ingest", core.Times{TS: &ts, RxTS: at, CapturedAt: at, Source: core.TimeBroadcast, Backlog: s.backlog},
		track.Body{TrackID: s.id, Trust: s.trust, Source: s.source, SourceInstance: s.inst,
			Position: track.Position{Lat: s.lat, Lng: s.lon}, AltAMSLM: s.altAMSL, AltWGS84M: s.wgs84, AltSource: s.altSrc, AltPressureM: s.press,
			Status: s.status, Identification: s.ident})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	return m
}

// at moves the clock to t0 + sec and sends s placed there.
func (r *rig) at(sec float64, ss ...sample) {
	r.t.Helper()
	now := t0.Add(time.Duration(sec * float64(time.Second)))
	r.clk.set(now)
	for i := range ss {
		if !r.w.Observe(message(r.t, ss[i], now)) {
			r.t.Fatalf("t=%v: %s not observed", sec, ss[i].id)
		}
	}
}

// tick moves the clock to t0 + sec and ticks.
func (r *rig) tick(sec float64) {
	r.clk.set(t0.Add(time.Duration(sec * float64(time.Second))))
	r.w.Tick(context.Background())
}

// zoneOf builds the judgement view of one ED-318 feature (uspace-core
// ed318.Parse and ToZones, as the projection reader does).
func zoneOf(t *testing.T, feature string) []*zones.Zone {
	t.Helper()
	fc, probs := ed318.Parse(wrapFeature([]byte(feature)), ed318.Limits{})
	if probs != nil {
		t.Fatalf("feature: %v", probs)
	}
	zs, err := ed318.ToZones(fc, ed318.NOAADaylight{})
	if err != nil {
		t.Fatal(err)
	}
	return zs
}

// zoneSpec describes a square ED-318 zone around (lat, lon).
type zoneSpec struct {
	id, typ            string
	lat, lon, halfDeg  float64
	lower, upper       float64
	lowerRef, upperRef string
	limited            string
}

func (z zoneSpec) feature() string {
	if z.typ == "" {
		z.typ = "PROHIBITED"
	}
	if z.halfDeg == 0 {
		z.halfDeg = 0.001
	}
	if z.lowerRef == "" {
		z.lowerRef = "AMSL"
	}
	if z.upperRef == "" {
		z.upperRef = "AMSL"
	}
	ring := fmt.Sprintf(`[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]]`,
		z.lon-z.halfDeg, z.lat-z.halfDeg, z.lon+z.halfDeg, z.lat-z.halfDeg, z.lon+z.halfDeg, z.lat+z.halfDeg,
		z.lon-z.halfDeg, z.lat+z.halfDeg, z.lon-z.halfDeg, z.lat-z.halfDeg)
	props := fmt.Sprintf(`"identifier":%q,"country":"GEO","name":[{"text":"Test zone","lang":"en-GB"}],"type":%q,"variant":"COMMON","reason":["SENSITIVE"],"zoneAuthority":[{"name":[{"text":"Test authority","lang":"en-GB"}],"purpose":"AUTHORIZATION"}]`,
		z.id, z.typ)
	if z.limited != "" {
		props += `,"limitedApplicability":` + z.limited
	}
	return fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":%s,"layer":{"lower":%g,"lowerReference":%q,"upper":%g,"upperReference":%q,"uom":"m"}},"properties":{%s}}`,
		ring, z.lower, z.lowerRef, z.upper, z.upperRef, props)
}

// byKind returns the messages of kind for aircraft id.
func byKind(ms []*violation.Message, kind violation.Kind, id string) []*violation.Message {
	var out []*violation.Message
	for _, m := range ms {
		if m.Body.Kind == kind && m.Body.TrackRef == id {
			out = append(out, m)
		}
	}
	return out
}

var (
	schemaOnce sync.Once
	schema     *jsonschema.Schema
	errSchema  error
)

// schemaCheck validates every published message against
// schemas/violation/v1.json (with the lab's envelope).
func schemaCheck(m *violation.Message) error {
	schemaOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.AssertFormat()
		for _, path := range []string{"../track/testdata/envelope/v1.json", "../../schemas/violation/v1.json"} {
			raw, err := os.ReadFile(path)
			if err != nil {
				errSchema = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				errSchema = err
				return
			}
			if err := c.AddResource(doc.(map[string]any)["$id"].(string), doc); err != nil {
				errSchema = err
				return
			}
		}
		schema, errSchema = c.Compile("https://schemas.uspace.ge/violation/v1.json")
	})
	if errSchema != nil {
		return errSchema
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return schema.Validate(inst)
}
