package detectsvc

import (
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The scenarios of uspace-lab knowledge/scenarios.md this detector owns,
// in process on a simulated clock: the worker cmd/detect runs, uspace-core's
// monitor, a recording publisher. Each asserts the raise and the clear
// (INV-02, E-01). The same flows against NATS and the databases are the
// integration tests (integration_test.go); the harness of internal/ltest
// is WP-25's.

const (
	zLat, zLon = 41.7151, 44.8271
	outLat     = 41.7251 // north of every test zone
)

// SC-07: a registered and an unidentified transmitter through a
// PROHIBITED zone: a zone violation for both, unregistered for the
// unidentified one only, and all three clear resolved together on exit.
func TestScenarioSC07UnidentifiedThroughAProhibitedZone(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.setZones(zoneOf(t, zoneSpec{id: "SC7", lat: zLat, lon: zLon, upper: 1500}.feature())...)
	alt := f64(800)
	reg := sample{id: "REG", altAMSL: alt}
	uni := sample{id: "UNI", altAMSL: alt, ident: unidentified(), inst: "rx-2"}
	out := func(s sample) sample { s.lat, s.lon = outLat, zLon; return s }
	in := func(s sample) sample { s.lat, s.lon = zLat, zLon; return s }
	r.at(0, out(reg), out(uni))
	if got := transitions(r.pub.take(), false); len(got) != 0 {
		t.Fatalf("outside: %s", describe(got))
	}
	r.at(1, in(reg), in(uni))
	raised := transitions(r.pub.take(), false)
	if len(raised) != 3 || len(byKind(raised, violation.KindZoneIncursion, "REG")) != 1 || len(byKind(raised, violation.KindZoneIncursion, "UNI")) != 1 ||
		len(byKind(raised, violation.KindUnregistered, "UNI")) != 1 || len(byKind(raised, violation.KindUnregistered, "REG")) != 0 {
		t.Fatalf("entry: %s", describe(raised))
	}
	for _, m := range raised {
		b := m.Body
		if b.State != violation.StateRaised || b.Severity != core.SeverityCritical || b.ZoneID == nil || *b.ZoneID != "GEO/SC7" ||
			b.ZoneVersion == nil || *b.ZoneVersion != 1 || b.PolicyVersion != 1 || b.EvidenceTrust != core.TrustBroadcast ||
			len(b.EvidenceExcerpt) == 0 || b.Cell5 == "" || m.CapturedAt != b.CapturedAt {
			t.Fatalf("raise body %+v", b)
		}
	}
	if u := byKind(raised, violation.KindUnregistered, "UNI")[0].Body; u.Detail["status"] != "unidentified" ||
		!slices.ContainsFunc(u.EvidenceRefs, func(e violation.EvidenceRef) bool { return e.Type == violation.RefReceiver && e.ID == "rx-2" }) {
		t.Fatalf("unregistered %+v", u)
	}
	ids := map[string]string{}
	for _, m := range raised {
		ids[m.Body.AlertKey] = m.Body.ViolationID
	}
	r.at(2, in(reg), in(uni))
	r.tick(2)
	r.at(3, out(reg), out(uni))
	r.at(4, out(reg), out(uni))
	if got := transitions(r.pub.take(), false); len(got) != 0 {
		t.Fatalf("within the hysteresis: %s", describe(got))
	}
	r.at(5.5, out(reg), out(uni))
	cleared := transitions(r.pub.take(), false)
	if len(cleared) != 3 {
		t.Fatalf("exit: %s", describe(cleared))
	}
	for _, m := range cleared {
		if m.Body.State != violation.StateCleared || *m.Body.ClearReason != "resolved" || ids[m.Body.AlertKey] != m.Body.ViolationID ||
			m.Body.ClosedAt == nil {
			t.Fatalf("clear %+v", m.Body)
		}
	}
}

// SC-04: constant AMSL over ground that falls; height_120m raised when
// AMSL minus the DEM first exceeds 120 m, with the dataset on it, and
// cleared after the hysteresis on the way back. Only the ground changes.
func TestScenarioSC04HeightLimitOverFallingGround(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	// A synthetic DEM: 1761 m at the start, falling 4 m per 0.001 deg north.
	r.in.env = func(p core.LatLon) zones.Env {
		return zones.Env{Ground: zones.GroundKnown, GroundM: 1761 - 4*math.Round((p.LatDeg-42.6)/0.001)}
	}
	r.in.elev = &terrain.Elevation{ElevationM: 1740, Dataset: "COP30-TEST", SpacingM: 30}
	alt := f64(1861)
	var raisedAt float64 = -1
	var heights []float64
	for i := 0; i <= 10; i++ {
		lat := 42.6 + float64(i)*0.001
		r.at(float64(i), sample{id: "SYS1", lat: lat, lon: 44.6, altAMSL: alt})
		heights = append(heights, 1861-(1761-float64(i)*4))
		if got := transitions(r.pub.take(), false); len(got) > 0 && raisedAt < 0 {
			raisedAt = float64(i)
			b := got[0].Body
			if len(got) != 1 || b.Kind != violation.KindHeight120m || b.Severity != core.SeverityWarning || b.Peak == nil ||
				b.Peak.Name != "height_agl_m" || b.Peak.Value <= 120 || b.TerrainSource == nil || b.TerrainSource.Dataset != "COP30-TEST" ||
				b.Detail["max_height_agl_m"] != 120.0 {
				t.Fatalf("raise %s %+v", describe(got), b)
			}
		}
	}
	// 100 m at the start, 104 at 1, ... 124 at 6: the first over 120.
	if raisedAt != 6 || heights[6] <= 120 || heights[5] > 120 {
		t.Fatalf("raised at %v, heights %v", raisedAt, heights)
	}
	r.tick(10)
	upd := r.pub.take()
	if len(upd) == 0 || upd[len(upd)-1].Body.Peak.Value != 140 {
		t.Fatalf("republished peak %s", describe(upd))
	}
	// Back to the start: under 120 m from i = 5 on the way back.
	var clearedAt float64 = -1
	for i := 0; i <= 10; i++ {
		lat := 42.6 + float64(10-i)*0.001
		r.at(11+float64(i), sample{id: "SYS1", lat: lat, lon: 44.6, altAMSL: alt})
		if got := transitions(r.pub.take(), false); len(got) > 0 {
			if len(got) != 1 || got[0].Body.State != violation.StateCleared || *got[0].Body.ClearReason != "resolved" || got[0].Body.Peak.Value != 140 {
				t.Fatalf("clear %s", describe(got))
			}
			clearedAt = 11 + float64(i)
			break
		}
	}
	// Last over 120 at t = 15 (124 m); at or under from 16; resolved once
	// shown false for more than 3 s after it: at 19.
	if clearedAt != 19 {
		t.Fatalf("cleared at %v", clearedAt)
	}
}

// SC-13: a PROHIBITED 0-120 m AGL zone with no DEM warns with
// limit_not_judged, and the status line is at error level naming it; a
// REQ_AUTHORISATION zone warns alike; a CONDITIONAL one raises nothing
// and counts not evaluated once per sample inside.
func TestScenarioSC13ProhibitedAGLZoneWithNoDEM(t *testing.T) {
	for _, typ := range []string{"PROHIBITED", "REQ_AUTHORIZATION"} {
		t.Run(typ, func(t *testing.T) {
			r := newRig(t, nil)
			r.in.setPolicy(1, nil)
			r.in.setZones(zoneOf(t, zoneSpec{id: "AGL1", typ: typ, lat: zLat, lon: zLon, lower: 0, upper: 120, lowerRef: "AGL", upperRef: "AGL"}.feature())...)
			r.at(0, sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(685.1)})
			got := transitions(r.pub.take(), false)
			if len(got) != 1 || got[0].Body.Severity != core.SeverityWarning || got[0].Body.Detail["limit_not_judged"] != true ||
				got[0].Body.Detail["vertical_known"] != false || !slices.Equal(got[0].Body.Detail["not_judged"].([]string), []string{"AGL"}) {
				t.Fatalf("raise %s %+v", describe(got), got)
			}
			for i := 1; i <= 5; i++ {
				r.at(float64(i), sample{id: "A", lat: outLat, lon: zLon, altAMSL: f64(685.1)})
			}
			got = transitions(r.pub.take(), false)
			if len(got) != 1 || *got[0].Body.ClearReason != "resolved" {
				t.Fatalf("clear %s", describe(got))
			}
			r.w.fold()
			if r.w.MonitorCounters.Get(zones.CounterZoneLimitNotJudged) != 1 {
				t.Fatal(r.w.MonitorCounters.Snapshot())
			}
		})
	}
	t.Run("CONDITIONAL", func(t *testing.T) {
		r := newRig(t, nil)
		r.in.setPolicy(1, nil)
		r.in.setZones(zoneOf(t, zoneSpec{id: "AGL2", typ: "CONDITIONAL", lat: zLat, lon: zLon, lower: 0, upper: 120, lowerRef: "AGL", upperRef: "AGL"}.feature())...)
		for i := range 4 {
			r.at(float64(i), sample{id: "A", lat: zLat, lon: zLon, altAMSL: f64(685.1)})
		}
		if got := transitions(r.pub.take(), false); len(got) != 0 {
			t.Fatalf("CONDITIONAL raised %s", describe(got))
		}
		r.w.fold()
		if n := r.w.MonitorCounters.Get(zones.CounterZoneNotEvaluated); n != 4 {
			t.Fatalf("not evaluated %d, want one per sample", n)
		}
	})
}

// SC-13 step 1 and Z-09: the error-level status names the PROHIBITED AGL
// zone without terrain; with terrain it says nothing of it (E-01).
func TestScenarioSC13StatusIsErrorLevelWhileAZoneNeedsGroundItLacks(t *testing.T) {
	zs := zoneOf(t, zoneSpec{id: "AGL1", lat: zLat, lon: zLon, lower: 0, upper: 120, lowerRef: "AGL", upperRef: "AGL"}.feature())
	in := &fakeInputs{}
	in.setZones(zs...)
	s := problemsOf(in, true, true)
	if len(s) != 2 || !strings.Contains(s[0], "PROHIBITED zone GEO/AGL1 needs terrain") {
		t.Fatalf("no terrain: %v", s)
	}
	if s := problemsOf(in, false, false); len(s) != 0 {
		t.Fatalf("with terrain: %v", s)
	}
}

// SC-12: applicability windows judged at captured_at: a permanent zone
// raises and clears; the same zone limited to a window that has ended
// raises nothing for samples inside it.
func TestScenarioSC12ApplicabilityWindowsInFlight(t *testing.T) {
	september := `[{"startDateTime":"2026-09-01T00:00:00Z","endDateTime":"2026-09-30T23:59:59Z"}]`
	run := func(t *testing.T, limited string) []*violation.Message {
		r := newRig(t, nil)
		r.in.setPolicy(1, nil)
		r.in.setZones(zoneOf(t, zoneSpec{id: "W1", lat: zLat, lon: zLon, lower: 600, upper: 800, limited: limited}.feature())...)
		for i := range 20 {
			r.at(float64(i), sample{id: "SYS3", lat: zLat, lon: zLon, altAMSL: f64(685.1)})
		}
		for i := 20; i < 26; i++ {
			r.at(float64(i), sample{id: "SYS3", lat: outLat, lon: zLon, altAMSL: f64(685.1)})
		}
		return transitions(r.pub.take(), false)
	}
	if got := run(t, ""); len(got) != 2 || got[0].Body.State != violation.StateRaised || got[1].Body.State != violation.StateCleared {
		t.Fatalf("permanent: %s", describe(got))
	}
	if got := run(t, september); len(got) != 0 {
		t.Fatalf("a window that ended: %s", describe(got))
	}
}

// SC-08 steps 2-5 (alert side): switching Remote ID off clears its
// aircraft's violation as source_disabled at once and refuses its
// samples; an aircraft of another source keeps its violation; switching
// it on raises again on the next sample.
func TestScenarioSC08SourceSwitchedOffAndOn(t *testing.T) {
	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.setZones(zoneOf(t, zoneSpec{id: "SW1", lat: zLat, lon: zLon, upper: 1500}.feature())...)
	rid := sample{id: "RID3", lat: zLat, lon: zLon, altAMSL: f64(500)}
	net := sample{id: "NET1", lat: zLat, lon: zLon, altAMSL: f64(500), source: track.SourceNetworkRID, inst: "ussp-a", trust: core.TrustProvider}
	r.at(0, rid, net)
	if got := transitions(r.pub.take(), false); len(got) != 2 {
		t.Fatalf("raised %s", describe(got))
	}
	r.in.setSources(coresources.State{Epoch: "e1", Version: 1, Controls: []coresources.Control{{SourceType: "direct_rid", Enabled: false}}})
	r.clk.set(t0.Add(1100 * 1e6))
	r.w.SwitchSources(t.Context())
	got := transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.TrackRef != "RID3" || *got[0].Body.ClearReason != "source_disabled" {
		t.Fatalf("switched off: %s", describe(got))
	}
	r.at(2, rid, net)
	if got := transitions(r.pub.take(), false); len(got) != 0 {
		t.Fatalf("a disabled source raised: %s", describe(got))
	}
	r.w.fold()
	if r.w.MonitorCounters.Get("rejected_source_disabled") != 1 {
		t.Fatal(r.w.MonitorCounters.Snapshot())
	}
	r.in.setSources(coresources.State{Epoch: "e1", Version: 2, Controls: []coresources.Control{{SourceType: "direct_rid", Enabled: true}}})
	r.w.SwitchSources(t.Context())
	r.at(2.5, rid)
	got = transitions(r.pub.take(), false)
	if len(got) != 1 || got[0].Body.TrackRef != "RID3" || got[0].Body.State != violation.StateRaised {
		t.Fatalf("switched on: %s", describe(got))
	}
}

// G-02: identification_mismatch from a registered serial broadcast with
// another operator's number, on the ground too; cleared when the
// identification says otherwise; and nothing from a backlog batch (T-04).
func TestScenarioIdentificationMismatchOnTheGroundAndNotFromBacklog(t *testing.T) {
	mismatch := core.Identification{Status: core.IdentUnknownOperator, Reason: core.ReasonOperatorMismatch, Serial: strp("TESTSER1"),
		OperatorReg: strp("GEO-TEST-X"), RegisteredOperatorReg: strp("GEO-TEST-Y"), Mismatch: true, Basis: core.BasisAsBroadcast}
	t.Run("live", func(t *testing.T) {
		r := newRig(t, nil)
		r.in.setPolicy(1, nil)
		r.at(0, sample{id: "M1", lat: zLat, lon: zLon, status: onGround(), ident: mismatch})
		got := transitions(r.pub.take(), false)
		if len(got) != 1 || got[0].Body.Kind != violation.KindIdentificationMismatch || got[0].Body.Severity != core.SeverityWarning ||
			*got[0].Body.OperatorReg != "GEO-TEST-X" {
			t.Fatalf("raise %s", describe(got))
		}
		for i := 1; i <= 5; i++ {
			r.at(float64(i), sample{id: "M1", lat: zLat, lon: zLon, status: onGround(), ident: registered("TESTSER1")})
		}
		if got := transitions(r.pub.take(), false); len(got) != 1 || *got[0].Body.ClearReason != "resolved" {
			t.Fatalf("clear %s", describe(got))
		}
	})
	t.Run("backlog", func(t *testing.T) {
		r := newRig(t, nil)
		r.in.setPolicy(1, nil)
		for i := range 5 {
			r.at(float64(i), sample{id: "M1", lat: zLat, lon: zLon, status: onGround(), ident: mismatch, backlog: true})
		}
		if got := transitions(r.pub.take(), false); len(got) != 0 {
			t.Fatalf("backlog raised %s", describe(got))
		}
		r.w.fold()
		if r.w.MonitorCounters.Get("rejected_backlog") != 5 {
			t.Fatal(r.w.MonitorCounters.Snapshot())
		}
	})
}

// problemsOf is Shared.Problems over in's zones with the ground absent
// or present.
func problemsOf(in *fakeInputs, noTerrain, noGeoid bool) []string {
	return problems(in.Zones(), nil, nil, noTerrain, noGeoid)
}
