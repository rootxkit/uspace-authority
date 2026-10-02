package ridpipe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/registry"
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// testRegistry is one active operator owning three aircraft: active,
// suspended, active (GEO-TEST numbers and TEST serials, rule 11).
func testRegistry(t testing.TB) func() identify.Lookup {
	t.Helper()
	owner := "00000000-0000-0000-0000-0000000000a1"
	return loadedRegistry(t,
		[]identify.OperatorFacts{{OperatorID: owner, RegistrationNumber: "GEOTEST00000001", Status: identify.StatusActive}},
		[]identify.UASFacts{
			{DroneID: "uas-reg", Serial: "TESTREG0001", RegistrationStatus: identify.StatusActive, OperatorID: &owner, InRegistry: true},
			{DroneID: "uas-sus", Serial: "TESTSUS0002", RegistrationStatus: identify.StatusSuspended, OperatorID: &owner, InRegistry: true},
			{DroneID: "uas-unk", Serial: "TESTUNK0003", RegistrationStatus: identify.StatusActive, OperatorID: &owner, InRegistry: true},
		})
}

// identified is one frame of a transmitter sending serial and operator
// with its Location: published at once.
func identified(t testing.TB, serial, operator string, l odid.Location) []byte {
	return frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: serial}, l, odid.OperatorID{OperatorID: operator})
}

// E-09, E-01: a refused frame is counted under its phrase and logged
// once, a second of the same kind is counted and not logged again, and
// the accepted frame beside them is decoded with no error.
func TestDecodeRefusalCountedByPhraseAndLoggedOnce(t *testing.T) {
	logs := &logBuffer{}
	lim := logging.NewLimiter(logs.logger(), time.Minute, 0, nil)
	p, _ := pipe(DefaultSettings(), Deps{Limiter: lim})
	good := identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg))
	b := batchOf("rx-1", t0, false,
		rxRow("rx-1", "TX-A", good[:24], at(t0)), // a 24-byte pack: refused whole (R-03)
		rxRow("rx-1", "TX-B", []byte{0x12, 1, 2}, at(t0)),
		rxRow("rx-1", "TX-C", good, at(t0)))
	observe(t, p, b)
	if b.Rows[0].DecodeError == nil || b.Rows[1].DecodeError == nil {
		t.Fatalf("refused frames without decode_error: %+v", b.Rows[:2])
	}
	if b.Rows[2].DecodeError != nil || b.Rows[2].Serial == nil || *b.Rows[2].Serial != "TESTREG0001" {
		t.Fatalf("accepted frame: %+v", b.Rows[2])
	}
	c := p.Counters()
	if c.Get(CounterDecodeRefused) != 2 {
		t.Fatalf("decode_refused %d", c.Get(CounterDecodeRefused))
	}
	kinds := 0
	for _, name := range c.Names() {
		if strings.HasPrefix(name, CounterDecodeRefused+"_") {
			kinds++
			if strings.ContainsAny(name, "0123456789 :,") {
				t.Errorf("counter name %q is not a stable snake_case phrase", name)
			}
		}
	}
	if kinds != 2 {
		t.Fatalf("%d refusal kinds counted: %v", kinds, c.Snapshot())
	}
	// The same refusal again: counted, not logged again.
	observe(t, p, batchOf("rx-1", t0.Add(time.Second), false, rxRow("rx-1", "TX-B", []byte{0x12, 9, 9}, at(t0.Add(time.Second)))))
	if c.Get(CounterDecodeRefused) != 3 {
		t.Fatalf("decode_refused %d", c.Get(CounterDecodeRefused))
	}
	if n := logs.count("Remote ID frame refused by the decoder; the raw frame is stored"); n != 2 {
		t.Fatalf("logged %d refusals, want the first of each of 2 kinds", n)
	}
}

// E-10: the refusal kinds are bounded; past 64 a new phrase is counted
// as other, and a kind already seen keeps its own counter.
func TestRefusalKindsAreBounded(t *testing.T) {
	p, _ := pipe(DefaultSettings(), Deps{})
	for i := range maxRefusalKinds + 6 {
		p.refused(&Row{}, &core.FieldError{Field: "frame", Reason: "kind " + string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	p.refused(&Row{}, &core.FieldError{Field: "frame", Reason: "kind aa"})
	c := p.Counters()
	if c.Get(CounterDecodeRefusedOther) != 6 || c.Get(CounterDecodeRefused+"_frame_kind_aa") != 2 || len(p.refusals) != maxRefusalKinds {
		t.Fatalf("other %d, first kind %d, kinds %d", c.Get(CounterDecodeRefusedOther), c.Get(CounterDecodeRefused+"_frame_kind_aa"), len(p.refusals))
	}
	if got := refusalKey(&core.FieldError{Field: "pack[3]", Reason: "pack of 12 messages"}); got != "pack_n_pack_of_n_messages" {
		t.Fatalf("key %q", got)
	}
	if got := refusalKey(errors.New(strings.Repeat("long phrase ", 20))); len(got) > 64 || strings.HasSuffix(got, "_") {
		t.Fatalf("key %q", got)
	}
}

// SC-22, G-08: before the projection has loaded every serial resolves
// registry_unavailable and is counted; once it loads the same aircraft
// is registered, and the change is announced on ident.v1 once.
func TestRegistryUnavailableUntilTheProjectionLoadsThenResolved(t *testing.T) {
	var lookup identify.Lookup
	reg := testRegistry(t)
	s := DefaultSettings()
	p, rec := pipe(s, Deps{Registry: func() identify.Lookup { return lookup }})
	send := func(i int) {
		now := t0.Add(time.Duration(i) * time.Second)
		observe(t, p, batchOf("rx-1", now, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(now))))
	}
	send(0)
	send(1)
	if p.Counters().Get(CounterRegistryUnavailable) != 2 {
		t.Fatalf("registry_unavailable %d", p.Counters().Get(CounterRegistryUnavailable))
	}
	lookup = reg()
	send(2)
	send(3)
	tracks := rec.tracks(t)
	want := []core.IdentReason{core.ReasonRegistryUnavailable, core.ReasonRegistryUnavailable, core.ReasonMatched, core.ReasonMatched}
	for i, m := range tracks {
		if m.Body.Identification.Reason != want[i] {
			t.Fatalf("track %d: %s, want %s", i, m.Body.Identification.Reason, want[i])
		}
	}
	idents := rec.idents(t)
	if len(idents) != 2 || idents[0].Body.Previous != nil || idents[1].Body.Previous == nil ||
		idents[1].Body.Previous.Reason != core.ReasonRegistryUnavailable || idents[1].Body.Identification.Status != core.IdentRegistered {
		t.Fatalf("ident changes %+v", idents)
	}
	if p.Counters().Get(CounterIdentChanges) != 2 || p.Counters().Get(CounterRegistryUnavailable) != 2 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
}

// R-07, SC-05 step 3: without a geoid there is no AMSL altitude, counted,
// and the status line says such aircraft are not judged vertically;
// with one, AMSL is HAE minus the undulation. A geoid that cannot answer
// at a position is counted and gives no AMSL either.
func TestAMSLOnlyThroughTheGeoid(t *testing.T) {
	run := func(d Deps) (*Pipeline, *float64, *float64) {
		p, rec := pipe(DefaultSettings(), d)
		observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(t0))))
		m := rec.tracks(t)[0]
		return p, m.Body.AltAMSLM, m.Body.AltWGS84M
	}
	p, amsl, hae := run(Deps{})
	if amsl != nil || hae == nil || *hae != 520 || p.Counters().Get(CounterAltNoGeoid) != 1 {
		t.Fatalf("no geoid: amsl %v hae %v %v", amsl, hae, p.Counters().Snapshot())
	}
	if !strings.Contains(attr(p.StatusAttrs(), "geoid"), "not judged vertically") {
		t.Fatalf("status %v", p.StatusAttrs())
	}
	p, amsl, _ = run(Deps{Geoid: constGeoid{15.9}})
	if amsl == nil || *amsl != 520-15.9 || p.Counters().Get(CounterAltGeodetic) != 1 || p.Counters().Get(CounterAltNoGeoid) != 0 {
		t.Fatalf("geoid: amsl %v %v", amsl, p.Counters().Snapshot())
	}
	if attr(p.StatusAttrs(), "geoid") != "configured" {
		t.Fatalf("status %v", p.StatusAttrs())
	}
	p, amsl, _ = run(Deps{Geoid: failingGeoid{}})
	if amsl != nil || p.Counters().Get(CounterGeoidFailed) != 1 {
		t.Fatalf("failing geoid: amsl %v %v", amsl, p.Counters().Snapshot())
	}
}

func attr(attrs []slog.Attr, key string) string {
	for _, a := range attrs {
		if a.Key == key {
			return a.Value.String()
		}
	}
	return ""
}

// R-08: a poor geodetic fix falls back to pressure, which goes in
// alt_pressure_m with alt_source pressure and never in alt_amsl_m.
func TestPressureAltitudeIsNeverAMSL(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{Geoid: constGeoid{15.9}})
	l := loc(baseLatDeg, baseLonDeg)
	l.VertAccuracy = 1
	observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", l), at(t0))))
	b := rec.tracks(t)[0].Body
	if b.AltAMSLM != nil || b.AltSource != core.AltPressure || b.AltPressureM == nil || *b.AltPressureM != 507.5 {
		t.Fatalf("amsl %v source %s pressure %v", b.AltAMSLM, b.AltSource, b.AltPressureM)
	}
	if p.Counters().Get(CounterAltPressure) != 1 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
}

// R-10: a speed without a direction is no velocity: all three null; with
// a direction, speed, track and climb are published.
func TestSpeedWithoutDirectionIsNoVelocity(t *testing.T) {
	for _, tc := range []struct {
		name string
		dir  *float64
		want bool
	}{{"no direction", nil, false}, {"direction", f64(90), true}} {
		p, rec := pipe(DefaultSettings(), Deps{})
		l := loc(baseLatDeg, baseLonDeg)
		l.DirectionDeg = tc.dir
		observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", l), at(t0))))
		b := rec.tracks(t)[0].Body
		got := b.SpeedMS != nil && b.TrackDeg != nil && b.VSpeedMS != nil
		none := b.SpeedMS == nil && b.TrackDeg == nil && b.VSpeedMS == nil
		if tc.want && (!got || *b.SpeedMS != 10 || *b.TrackDeg != 90 || *b.VSpeedMS != 1.5) || !tc.want && !none {
			t.Fatalf("%s: speed %v track %v climb %v", tc.name, b.SpeedMS, b.TrackDeg, b.VSpeedMS)
		}
		if (p.Counters().Get(CounterVelocityUnknown) == 1) == tc.want {
			t.Fatalf("%s: velocity_unknown %d", tc.name, p.Counters().Get(CounterVelocityUnknown))
		}
	}
}

// R-11: only Ground is not airborne; an emergency is published as one.
func TestStatusAirborneAndEmergency(t *testing.T) {
	for _, tc := range []struct {
		st        odid.Status
		airborne  bool
		emergency bool
		name      string
	}{{odid.StatusGround, false, false, "Ground"}, {odid.StatusUndeclared, true, false, "Undeclared"},
		{odid.StatusEmergency, true, true, "Emergency"}, {odid.StatusRemoteIDSystemFailure, true, false, "RemoteIDSystemFailure"}} {
		p, rec := pipe(DefaultSettings(), Deps{})
		l := loc(baseLatDeg, baseLonDeg)
		l.Status = tc.st
		b := batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", l), at(t0)))
		observe(t, p, b)
		m := rec.tracks(t)[0]
		if m.Body.Status == nil || string(*m.Body.Status) != tc.name || m.Body.Emergency != tc.emergency ||
			b.Tracks[0].Airborne == nil || *b.Tracks[0].Airborne != tc.airborne || *b.Rows[0].Status != tc.name {
			t.Fatalf("%s: %+v airborne %v", tc.name, m.Body, b.Tracks[0].Airborne)
		}
	}
	if statusName(odid.Status(9)) != nil || heightRef(odid.HeightReference(3)) != nil {
		t.Fatal("an undefined value got a name")
	}
}

// T-12: a row without the receiver's rx_ts is received at its arrival
// and counted; its broadcast time is still believed against that, and
// when it is not, it is placed at arrival with time_source system.
func TestRowWithoutRxTSIsReceivedAtArrival(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{})
	sah := float64(t0.Add(-300*time.Millisecond).Minute()*60+t0.Add(-300*time.Millisecond).Second()) + 0.7
	l := loc(baseLatDeg, baseLonDeg)
	l.SecondsAfterHour = &sah
	unknown := loc(baseLatDeg, baseLonDeg)
	b := batchOf("rx-1", t0, false,
		rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", l), nil),
		rxRow("rx-1", "TX-2", identified(t, "TESTREG0002", "GEOTEST00000001", unknown), nil))
	observe(t, p, b)
	if p.Counters().Get(CounterRxTSMissing) != 2 || p.Counters().Get(CounterPlacedArrival) != 1 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
	if *b.Rows[0].TimeSource != "broadcast" || !b.Rows[0].CapturedAt.Equal(t0.Add(-300*time.Millisecond)) {
		t.Fatalf("believed broadcast: %s %v", *b.Rows[0].TimeSource, b.Rows[0].CapturedAt)
	}
	if *b.Rows[1].TimeSource != "system" || !b.Rows[1].CapturedAt.Equal(t0) || b.Rows[1].TSBroadcast != nil {
		t.Fatalf("unknown broadcast time: %s %v", *b.Rows[1].TimeSource, b.Rows[1].CapturedAt)
	}
	ms := rec.tracks(t)
	if ms[1].TimeSource != core.TimeSystem || ms[1].TS != nil {
		t.Fatalf("envelope %s ts %v", ms[1].TimeSource, ms[1].TS)
	}
}

// T-02: the rows of one batch keep their spacing on this system's clock
// whatever the receiver's clock says, and a spacing past the bound is
// clamped and counted.
func TestBatchRowsKeepTheirSpacing(t *testing.T) {
	p, _ := pipe(DefaultSettings(), Deps{})
	skewed := t0.Add(-7 * time.Hour) // the receiver's clock is hours off
	frameOf := func(tx string) []byte { return frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TEST" + tx}) }
	b := batchOf("rx-1", t0, false,
		rxRow("rx-1", "A", frameOf("A"), at(skewed)),
		rxRow("rx-1", "B", frameOf("B"), at(skewed.Add(500*time.Millisecond))),
		rxRow("rx-1", "C", frameOf("C"), at(skewed.Add(-10*time.Minute))))
	observe(t, p, b)
	if !b.Rows[1].CapturedAt.Equal(t0) || !b.Rows[0].CapturedAt.Equal(t0.Add(-500*time.Millisecond)) ||
		!b.Rows[2].CapturedAt.Equal(t0.Add(-120*time.Second)) || *b.Rows[0].TimeSource != "source_clock" {
		t.Fatalf("placed %v %v %v", b.Rows[0].CapturedAt, b.Rows[1].CapturedAt, b.Rows[2].CapturedAt)
	}
	if p.Counters().Get(CounterRxSpacingClamped) != 1 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
}

// T-04: backlog rows have their own tracker. A live receiver borrows a
// fresh identity another live receiver heard (I-03); a backlog Location
// of the same transmitter does not, and its track says backlog.
func TestBacklogNeverBorrowsALiveIdentity(t *testing.T) {
	s := DefaultSettings()
	s.Tracker.IdentifyWithinS = rid.IdentifyAtOnceS
	p, rec := pipe(s, Deps{})
	observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTREG0001"}), at(t0))))
	now := t0.Add(time.Second)
	observe(t, p, batchOf("rx-2", now, false, rxRow("rx-2", "TX-1", frame(t, loc(baseLatDeg, baseLonDeg)), at(now))))
	observe(t, p, batchOf("rx-3", now, true, rxRow("rx-3", "TX-1", frame(t, loc(baseLatDeg, baseLonDeg)), at(now))))
	ms := rec.tracks(t)
	if len(ms) != 2 {
		t.Fatalf("%d tracks", len(ms))
	}
	if ms[0].Body.TrackID != rid.AircraftID(odid.IDTypeSerial, "TESTREG0001") || ms[0].Backlog {
		t.Fatalf("live: %s backlog %v", ms[0].Body.TrackID, ms[0].Backlog)
	}
	if ms[1].Body.TrackID != rid.UnidentifiedID("TX-1") || !ms[1].Backlog {
		t.Fatalf("backlog: %s backlog %v", ms[1].Body.TrackID, ms[1].Backlog)
	}
	live, backlog := p.TrackerCounters()
	if live.Get(rid.CounterUnidentified) != 0 || backlog.Get(rid.CounterUnidentified) != 1 {
		t.Fatalf("live %v backlog %v", live.Snapshot(), backlog.Snapshot())
	}
}

// The trackers' clock never goes back: a row received before the clock
// is taken at the clock and counted.
func TestTrackerClockNeverGoesBack(t *testing.T) {
	p, _ := pipe(DefaultSettings(), Deps{})
	bid := frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTREG0001"})
	observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", bid, at(t0))))
	if p.Counters().Get(CounterTrackerClockHeld) != 0 {
		t.Fatal("held on the first row")
	}
	earlier := t0.Add(-2 * time.Second)
	observe(t, p, batchOf("rx-2", earlier, false, rxRow("rx-2", "TX-1", bid, at(earlier))))
	if p.Counters().Get(CounterTrackerClockHeld) != 1 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
}

// I-01: the tick forgets a transmitter silent past the gap, and only
// then.
func TestTickForgetsSilentTransmitters(t *testing.T) {
	p, _ := pipe(DefaultSettings(), Deps{Now: func() time.Time { return t0 }})
	observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTREG0001"}), at(t0))))
	live, _ := p.TrackerCounters()
	p.Tick(t0.Add(2 * time.Second))
	if live.Get(rid.CounterSilences) != 0 || p.live.t.Transmitters() != 1 {
		t.Fatal("forgot within the gap")
	}
	p.Tick(t0.Add(4 * time.Second))
	if live.Get(rid.CounterSilences) != 1 || p.live.t.Transmitters() != 0 {
		t.Fatalf("not forgotten past the gap: %v", live.Snapshot())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(ctx, time.Millisecond) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
}

// E-10: the tracker's transmitter table is bounded; past it the address
// heard longest ago is evicted and counted.
func TestTrackerTransmitterBound(t *testing.T) {
	s := DefaultSettings()
	s.Tracker.MaxTransmitters = 2
	p, _ := pipe(s, Deps{})
	for i, tx := range []string{"TX-1", "TX-2", "TX-3"} {
		now := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		observe(t, p, batchOf("rx-1", now, false, rxRow("rx-1", tx, frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TEST" + tx}), at(now))))
	}
	live, _ := p.TrackerCounters()
	if live.Get(rid.CounterEvicted) != 1 || p.live.t.Transmitters() != 2 {
		t.Fatalf("evicted %d, held %d", live.Get(rid.CounterEvicted), p.live.t.Transmitters())
	}
}

// E-10: the per-track memories (last identification, altitude hold) are
// bounded; an evicted track id announces its identification again, a
// held one does not.
func TestIdentChangeMemoryBound(t *testing.T) {
	s := DefaultSettings()
	s.MaxTracks = 2
	p, rec := pipe(s, Deps{})
	send := func(i int, serial string) {
		now := t0.Add(time.Duration(i) * 100 * time.Millisecond)
		observe(t, p, batchOf("rx-1", now, false, rxRow("rx-1", "TX-"+serial, identified(t, serial, "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(now))))
	}
	send(0, "TESTA")
	send(1, "TESTB")
	send(2, "TESTA") // held: no second announcement
	if n := len(rec.idents(t)); n != 2 {
		t.Fatalf("%d announcements, want 2", n)
	}
	send(3, "TESTC") // evicts TESTB
	send(4, "TESTB") // announced again
	if n := len(rec.idents(t)); n != 4 {
		t.Fatalf("%d announcements, want 4", n)
	}
	c := p.Counters()
	if c.Get(CounterIdentMemoryEvicted) != 2 || c.Get(CounterAltHoldsEvicted) != 2 || p.idents.len() != 2 || p.alts.len() != 2 {
		t.Fatalf("%v", c.Snapshot())
	}
}

// The tracks rows of a batch: one per published track, keyed by the
// frame that carried the Location, even when the Location was held for
// its identity and published by a later frame (I-02) with its own row's
// times; a frame that publishes nothing adds no row.
func TestTracksRowsKeyedByTheLocationRow(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{})
	sah := float64(t0.Minute()*60+t0.Second()) + 0.0
	l := loc(baseLatDeg, baseLonDeg)
	l.SecondsAfterHour = &sah
	locRow := rxRow("rx-1", "TX-1", frame(t, l), at(t0))
	b1 := batchOf("rx-1", t0, false, locRow)
	observe(t, p, b1)
	if len(b1.Tracks) != 0 || len(rec.tracks(t)) != 0 {
		t.Fatal("a Location without an identity published at once")
	}
	later := t0.Add(1500 * time.Millisecond)
	b2 := batchOf("rx-1", later, false, rxRow("rx-1", "TX-1", frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTREG0001"}), at(later)))
	observe(t, p, b2)
	if len(b2.Tracks) != 1 {
		t.Fatalf("%d rows", len(b2.Tracks))
	}
	r := b2.Tracks[0]
	if r.DedupeKey != "direct_rid:"+locRow.FrameID || !r.CapturedAt.Equal(t0) || !r.RxTS.Equal(t0) || r.TimeSource != core.TimeBroadcast ||
		r.TrackID != rid.AircraftID(odid.IDTypeSerial, "TESTREG0001") || r.LatDeg != baseLatDeg || r.Source != "direct_rid" {
		t.Fatalf("row %+v", r)
	}
	if p.Counters().Get(CounterPlacementMissed) != 0 {
		t.Fatal("the held Location's placement was not kept")
	}
}

// E-09: a track or identification that cannot be published is counted;
// its tracks row is still kept for storage.
func TestPublishFailuresAreCounted(t *testing.T) {
	rec := &recorder{err: errors.New("nats: connection closed")}
	p, _ := pipe(DefaultSettings(), Deps{Publisher: rec})
	b := batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(t0)))
	observe(t, p, b)
	c := p.Counters()
	if c.Get(CounterPublishFailed) != 1 || c.Get(CounterIdentPublishFailed) != 1 || c.Get(CounterPublished) != 0 || len(b.Tracks) != 1 {
		t.Fatalf("%v rows %d", c.Snapshot(), len(b.Tracks))
	}
}

// R-01: a Location without a position publishes no track and is
// counted; its twin with a position publishes one.
func TestLocationWithoutPositionPublishesNoTrack(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{})
	l := loc(baseLatDeg, baseLonDeg)
	l.LatDeg, l.LonDeg = nil, nil
	observe(t, p, batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", l), at(t0))))
	if len(rec.tracks(t)) != 0 || p.Counters().Get(CounterNoPosition) != 1 {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
	now := t0.Add(time.Second)
	observe(t, p, batchOf("rx-1", now, false, rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(now))))
	if len(rec.tracks(t)) != 1 {
		t.Fatal("no track with a position")
	}
}

// A frame of skipped messages only (R-04) publishes nothing and is
// counted; Self-ID text never reaches a column.
func TestSkippedMessagesOnly(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{})
	b := batchOf("rx-1", t0, false, rxRow("rx-1", "TX-1", frame(t, odid.SelfID{Description: "TEST hello"}), at(t0)))
	observe(t, p, b)
	if p.Counters().Get(CounterFramesSkipped) != 1 || len(rec.tracks(t)) != 0 || b.Rows[0].DecodeError != nil {
		t.Fatalf("%v", p.Counters().Snapshot())
	}
}

// The projection reader's status says whether it ever loaded (SC-22).
func TestProjectionReaderStatusBeforeAndAfter(t *testing.T) {
	r := &registry.ProjectionReader{Source: failingProjection{}}
	if err := r.Refresh(context.Background()); err == nil || r.Lookup() != nil {
		t.Fatal("a failed read gave a lookup")
	}
	if attr(r.StatusAttrs(), "projection_loaded") != "false" {
		t.Fatalf("%v", r.StatusAttrs())
	}
	ok := &registry.ProjectionReader{Source: fixedProjection{}}
	if err := ok.Refresh(context.Background()); err != nil || ok.Lookup() == nil || attr(ok.StatusAttrs(), "projection_loaded") != "true" {
		t.Fatalf("%v %v", err, ok.StatusAttrs())
	}
}

type failingProjection struct{}

func (failingProjection) LoadProjection(context.Context) (registry.Loaded, error) {
	return registry.Loaded{}, fmt.Errorf("telemetry database: connection refused")
}

func TestNewDefaults(t *testing.T) {
	p := New(Settings{}, Deps{Publisher: &recorder{}})
	s := p.Settings()
	if s.MaxTracks != 50000 || s.Producer != "authority/rid-ingest" || s.Tracker.IdentityTTLS != 15 || p.Counters() == nil {
		t.Fatalf("%+v", s)
	}
}
