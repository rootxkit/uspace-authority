package ridpipe

import (
	"context"
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/identify"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/track"
)

// The Remote ID scenarios of uspace-lab knowledge/scenarios.md that this
// pipeline owns, run in process on simulated clocks (internal/ltest, the
// harness that runs them against NATS and the databases, is WP-25). A
// simulated receiver encodes each datagram with odid.Encode and posts it
// as a batch; the pipeline is the one rid-ingest runs.

// sahOf is the Location timestamp of a broadcast sent at t: tenths of a
// second after the UTC hour, as the field holds them (T-07).
func sahOf(t time.Time) *float64 {
	tenths := (t.Sub(t.Truncate(time.Hour))) / (100 * time.Millisecond)
	v := float64(tenths) / 10
	return &v
}

// datagram is one message a transmitter sent at a time.
type datagram struct {
	at  time.Time
	msg odid.Message
}

// leg is a module broadcasting serial from transmitter address tx for n
// seconds from start: a Location every second and its Basic ID every
// three (Bluetooth 4: one message per datagram).
func leg(start time.Time, n int, serial string) []datagram {
	var out []datagram
	for s := range n {
		now := start.Add(time.Duration(s) * time.Second)
		if s%3 == 0 {
			out = append(out, datagram{now, odid.BasicID{IDType: odid.IDTypeSerial, UAID: serial}})
		}
		l := loc(baseLatDeg+float64(s)*1e-4, baseLonDeg)
		at := now.Add(200 * time.Millisecond)
		l.SecondsAfterHour = sahOf(at)
		out = append(out, datagram{at, l})
	}
	return out
}

// sc10 runs SC-10 with seed under settings s: two 30 s legs on one
// address, the second a restart 4 s later with a new serial, 30 % of the
// datagrams dropped. It returns the Locations published under the old
// serial after the restart and under the new one, and whether the seed
// is the one the scenario wants (the restart's first Basic ID dropped,
// two Locations through before the next Basic ID that arrives).
func sc10(t *testing.T, seed uint64, s Settings, run bool) (oldAfter, newRows int, wanted bool) {
	t.Helper()
	oldAfter, newRows, wanted, _ = sc10Run(t, seed, s, run, false)
	return oldAfter, newRows, wanted
}

// sc10Backlog replays SC-10's datagrams as backlog an hour later, while
// the process ticks on wall time, and returns tracker_clock_held too.
func sc10Backlog(t *testing.T, seed uint64) (oldAfter, newRows int, held uint64) {
	t.Helper()
	oldAfter, newRows, _, p := sc10Run(t, seed, DefaultSettings(), true, true)
	return oldAfter, newRows, p.Counters().Get(CounterTrackerClockHeld)
}

func sc10Run(t *testing.T, seed uint64, s Settings, run, backlog bool) (oldAfter, newRows int, wanted bool, p *Pipeline) {
	t.Helper()
	const tx = "AA:BB:CC:00:10:01"
	restart := t0.Add(34 * time.Second)
	sent := append(leg(t0, 30, "TESTOLD0001"), leg(restart, 30, "TESTNEW0002")...)
	rng := rand.New(rand.NewPCG(seed, 10))
	kept := make([]bool, len(sent))
	for i := range sent {
		kept[i] = rng.Float64() >= 0.30
	}
	// The scenario's seed: the first datagram of the restart (its Basic
	// ID) dropped, then exactly two Locations through before a Basic ID
	// gets through.
	first := 0
	for sent[first].at.Before(restart) {
		first++
	}
	if !kept[first] {
		through := 0
		for i := first + 1; i < len(sent); i++ {
			if _, isID := sent[i].msg.(odid.BasicID); isID && kept[i] {
				break
			}
			if kept[i] {
				through++
			}
		}
		wanted = through == 2
	}
	if !run {
		return 0, 0, wanted, nil
	}
	p, rec := pipe(s, Deps{})
	oldID, newID := rid.AircraftID(odid.IDTypeSerial, "TESTOLD0001"), rid.AircraftID(odid.IDTypeSerial, "TESTNEW0002")
	lastTick := t0
	replay := time.Duration(0)
	if backlog {
		replay = time.Hour // delivered an hour after it was heard
	}
	for i, d := range sent {
		for d.at.Sub(lastTick) >= time.Second { // the process's once-a-second tick, on wall time
			lastTick = lastTick.Add(time.Second)
			p.Tick(lastTick.Add(replay))
		}
		if !kept[i] {
			continue
		}
		observe(t, p, batchOf("rx-1", d.at, backlog, rxRow("rx-1", tx, frame(t, d.msg), at(d.at))))
	}
	tracks := rec.tracks(t)
	for i := range tracks {
		m := &tracks[i]
		captured, err := time.Parse(time.RFC3339Nano, m.CapturedAt)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case m.Body.TrackID == oldID && !captured.Before(restart):
			oldAfter++
		case m.Body.TrackID == newID:
			newRows++
		}
	}
	return oldAfter, newRows, wanted, p
}

// SC-10 (S-32, I-01): a serial change on a reused address with 30 %
// drops stores no Location under the old serial after the restart; the
// control under the old 60 s rules stores two with the same seed, so the
// scenario can detect the bug (E-01). Twenty further seeds store none
// under the old serial.
func TestScenarioSC10SerialChangeOnAReusedAddressWithDrops(t *testing.T) {
	var seed uint64
	for s := uint64(1); s < 100000; s++ {
		if _, _, ok := sc10(t, s, DefaultSettings(), false); ok {
			seed = s
			break
		}
	}
	if seed == 0 {
		t.Fatal("no seed drops the restart's first Basic ID with two Locations through")
	}
	old, newRows, _ := sc10(t, seed, DefaultSettings(), true)
	if old != 0 {
		t.Fatalf("seed %d: %d Locations stored under the old serial after the restart", seed, old)
	}
	if newRows == 0 {
		t.Fatalf("seed %d: nothing stored under the new serial", seed)
	}
	control := DefaultSettings()
	control.Tracker.IdentityTTLS, control.Tracker.MaxGapS = 60, 60
	cOld, _, _ := sc10(t, seed, control, true)
	if cOld != 2 {
		t.Fatalf("control (60 s identity, 60 s memory), seed %d: %d Locations under the old serial, want 2", seed, cOld)
	}
	clean := 0
	for s := seed + 1; clean < 20; s++ {
		o, _, _ := sc10(t, s, DefaultSettings(), true)
		if o != 0 {
			t.Fatalf("seed %d: %d Locations under the old serial after the restart", s, o)
		}
		clean++
	}
	t.Logf("SC-10 seed %d: 0 under the old serial after the restart, %d under the new; control with the old rules: %d under the old; 20 further seeds: 0",
		seed, newRows, cOld)
}

// SC-11 (S-27, T-07): every datagram delivered 2 s late, no drops: every
// observation is placed at its broadcast time, about 2 s before its
// receipt (the field holds tenths). The control without a broadcast time
// places them at receipt, so the scenario can tell the two apart.
func TestScenarioSC11ReceiverLatency(t *testing.T) {
	run := func(withTime bool) (lags []float64, sources map[core.TimeSource]int) {
		p, rec := pipe(DefaultSettings(), Deps{})
		for s := range 60 {
			heard := t0.Add(time.Duration(s)*time.Second + time.Duration(s*17%100)*time.Millisecond)
			l := loc(baseLatDeg, baseLonDeg)
			if withTime {
				l.SecondsAfterHour = sahOf(heard)
			}
			delivered := heard.Add(2 * time.Second)
			payload := frame(t, odid.BasicID{IDType: odid.IDTypeSerial, UAID: "TESTLAT0001"}, l)
			observe(t, p, batchOf("rx-1", delivered, false, rxRow("rx-1", "TX-LAT", payload, at(heard))))
		}
		sources = map[core.TimeSource]int{}
		for _, m := range rec.tracks(t) {
			rx, _ := time.Parse(time.RFC3339Nano, m.RxTS)
			captured, _ := time.Parse(time.RFC3339Nano, m.CapturedAt)
			lags = append(lags, rx.Sub(captured).Seconds())
			sources[m.TimeSource]++
		}
		return lags, sources
	}
	lags, sources := run(true)
	if len(lags) != 60 || sources[core.TimeBroadcast] != 60 {
		t.Fatalf("%d tracks, sources %v", len(lags), sources)
	}
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, l := range lags {
		lo, hi = math.Min(lo, l), math.Max(hi, l)
	}
	if lo < 1.9 || hi > 2.1 {
		t.Fatalf("placed %.3f to %.3f s before receipt, want about 2 s (tenths)", lo, hi)
	}
	cLags, cSources := run(false)
	if cSources[core.TimeReceiver] != 60 || cLags[0] != 0 {
		t.Fatalf("control: %v %v", cSources, cLags[:1])
	}
	t.Logf("SC-11: 60 observations placed at broadcast time %.3f to %.3f s before receipt; control without a timestamp: all at receipt", lo, hi)
}

// SC-06 rows 1, 2 (direct), 3 and 5 as the authority sees them: four
// transmitters at once against one projection, Bluetooth 4 datagrams.
func TestScenarioSC06FourIdentificationStatuses(t *testing.T) {
	p, rec := pipe(DefaultSettings(), Deps{Registry: testRegistry(t), Geoid: constGeoid{15.9}})
	type transmitter struct {
		addr, serial, operator string
	}
	txs := []transmitter{
		{"AA:BB:CC:00:06:01", "TESTREG0001", "GEOTEST00000001-x9z"}, // row 1, with its secret suffix
		{"AA:BB:CC:00:06:02", "TESTSUS0002", "GEOTEST00000001"},     // row 2, direct
		{"AA:BB:CC:00:06:03", "TESTUNK0003", "GEOTEST00000099"},     // row 3
		{"AA:BB:CC:00:06:05", "", ""},                               // row 5: SYSID 1's second transmitter, no Basic ID
	}
	for s := range 10 {
		for i, tx := range txs {
			now := t0.Add(time.Duration(s)*time.Second + time.Duration(i)*10*time.Millisecond)
			var msgs []odid.Message
			if s%3 == 0 && tx.serial != "" {
				msgs = append(msgs, odid.BasicID{IDType: odid.IDTypeSerial, UAID: tx.serial}, odid.OperatorID{OperatorID: tx.operator})
			}
			l := loc(baseLatDeg, baseLonDeg+float64(i%3)*1e-3)
			l.SecondsAfterHour = sahOf(now)
			msgs = append(msgs, l)
			var rows []Row
			for _, m := range msgs { // one message per datagram
				rows = append(rows, rxRow("rx-1", tx.addr, frame(t, m), at(now)))
			}
			observe(t, p, batchOf("rx-1", now, false, rows...))
		}
	}
	want := map[string]struct {
		status   core.IdentStatus
		reason   core.IdentReason
		mismatch bool
		reg      *string
	}{
		rid.AircraftID(odid.IDTypeSerial, "TESTREG0001"): {core.IdentRegistered, core.ReasonMatched, false, nil},
		rid.AircraftID(odid.IDTypeSerial, "TESTSUS0002"): {core.IdentSuspended, core.ReasonUASSuspended, false, nil},
		rid.AircraftID(odid.IDTypeSerial, "TESTUNK0003"): {core.IdentUnknownOperator, core.ReasonOperatorMismatch, true, strPtr("GEOTEST00000001")},
		rid.UnidentifiedID("AA:BB:CC:00:06:05"):          {core.IdentUnidentified, core.ReasonNoSerial, false, nil},
	}
	seen := map[string]int{}
	for _, m := range rec.tracks(t) {
		w, ok := want[m.Body.TrackID]
		if !ok {
			t.Fatalf("unexpected track %s (%s)", m.Body.TrackID, m.Body.Identification.Reason)
		}
		id := m.Body.Identification
		if id.Status != w.status || id.Reason != w.reason || id.Mismatch != w.mismatch || id.Basis != core.BasisAsBroadcast {
			t.Fatalf("%s: %s/%s/%v, want %s/%s/%v", m.Body.TrackID, id.Status, id.Reason, id.Mismatch, w.status, w.reason, w.mismatch)
		}
		if (w.reg == nil) != (id.RegisteredOperatorReg == nil) || w.reg != nil && *id.RegisteredOperatorReg != *w.reg {
			t.Fatalf("%s: registered_operator_reg %v", m.Body.TrackID, deref(id.RegisteredOperatorReg))
		}
		if m.Body.AltAMSLM == nil || m.Body.Trust != core.TrustBroadcast || m.Body.Source != track.SourceDirectRID {
			t.Fatalf("%s: %+v", m.Body.TrackID, m.Body)
		}
		seen[m.Body.TrackID]++
	}
	if len(seen) != 4 {
		t.Fatalf("tracks %v", seen)
	}
	// Each identification announced once: none changes while broadcast.
	ann := map[string]int{}
	for _, c := range rec.idents(t) {
		ann[c.Body.TrackID]++
	}
	for id := range want {
		if ann[id] != 1 {
			t.Fatalf("%s announced %d times", id, ann[id])
		}
	}
	t.Logf("SC-06: four statuses at once, tracks published %v", seen)
}

// SC-22: no geoid and no projection: the aircraft are on the map with no
// AMSL altitude and with identification registry_unavailable (no_serial
// for the one without a serial), and both are on the status line. The
// same broadcasts with a geoid and a loaded projection are judged.
func TestScenarioSC22NoGeoidNoProjection(t *testing.T) {
	reader := &registry.ProjectionReader{Source: failingProjection{}}
	_ = reader.Refresh(context.Background())
	s := DefaultSettings()
	s.Tracker.IdentifyWithinS = rid.IdentifyAtOnceS
	send := func(p *Pipeline) {
		observe(t, p, batchOf("rx-1", t0, false,
			rxRow("rx-1", "TX-1", identified(t, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg, baseLonDeg)), at(t0)),
			rxRow("rx-1", "TX-2", frame(t, loc(baseLatDeg, baseLonDeg)), at(t0))))
	}
	p, rec := pipe(s, Deps{Registry: reader.Lookup})
	send(p)
	ms := rec.tracks(t)
	if len(ms) != 2 {
		t.Fatalf("%d tracks: an empty console must never look like an empty sky", len(ms))
	}
	for _, m := range ms {
		if m.Body.AltAMSLM != nil || m.Body.AltSource != core.AltNone {
			t.Fatalf("%s: AMSL %v without a geoid", m.Body.TrackID, *m.Body.AltAMSLM)
		}
	}
	if r := ms[0].Body.Identification.Reason; r != core.ReasonRegistryUnavailable {
		t.Fatalf("serial resolved %s without a projection", r)
	}
	if r := ms[1].Body.Identification.Reason; r != core.ReasonNoSerial {
		t.Fatalf("no serial resolved %s", r)
	}
	if attr(p.StatusAttrs(), "geoid") == "configured" || attr(reader.StatusAttrs(), "projection_loaded") != "false" ||
		p.Counters().Get(CounterAltNoGeoid) != 2 || p.Counters().Get(CounterRegistryUnavailable) != 1 {
		t.Fatalf("status %v %v counters %v", p.StatusAttrs(), reader.StatusAttrs(), p.Counters().Snapshot())
	}
	p2, rec2 := pipe(s, Deps{Registry: testRegistry(t), Geoid: constGeoid{15.9}})
	send(p2)
	ok := rec2.tracks(t)
	if ok[0].Body.AltAMSLM == nil || ok[0].Body.Identification.Status != core.IdentRegistered {
		t.Fatalf("with a geoid and a projection: %+v", ok[0].Body)
	}
}

// BenchmarkPipelineObserve is one observation through every step (plan
// §8: at most 200 µs per observation at one core): a pack of Basic ID,
// Location and Operator ID from one of 1000 transmitters, with a geoid
// and a loaded projection.
func BenchmarkPipelineObserve(b *testing.B) {
	p, _ := pipe(DefaultSettings(), Deps{Registry: testRegistry(b), Geoid: constGeoid{15.9}, Publisher: discard{}})
	const n = 1000
	payloads := make([][]byte, n)
	addrs := make([]string, n)
	for i := range n {
		payloads[i] = identified(b, "TESTREG0001", "GEOTEST00000001", loc(baseLatDeg+float64(i)*1e-4, baseLonDeg))
		addrs[i] = "TX-" + string(rune('A'+i%26)) + string(rune('A'+i/26%26)) + string(rune('A'+i/676))
	}
	rows := make([]Row, n)
	for i := range n {
		rows[i] = rxRow("rx-1", addrs[i], payloads[i], nil)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		now := t0.Add(time.Duration(i) * time.Millisecond)
		r := rows[i%n]
		r.ReceiverTS = &now
		bt := Batch{ID: "b", ReceiverID: "rx-1", IngestTS: now, Rows: []Row{r}}
		_ = p.Observe(context.Background(), &bt)
	}
}

// discard is a publisher that drops everything (the benchmark measures
// the pipeline, not NATS).
type discard struct{}

func (discard) Publish(string, []byte) error { return nil }

var _ identify.Lookup = (*identify.Snapshot)(nil)
