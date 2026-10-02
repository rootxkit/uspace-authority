package picture

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// A box inside one c5 cell covers that cell and its eight neighbours
// (05 §3's margin); at nine cells it is accepted, at eight refused naming
// bbox (E-10 pair).
func TestViewportIsTheCoverWithAOneCellMargin(t *testing.T) {
	box := geodesy.BBox{MinLat: 41.71, MinLon: 44.81, MaxLat: 41.72, MaxLon: 44.82}
	cells, err := ViewportCells(box, 9)
	if err != nil {
		t.Fatal(err)
	}
	if len(cells) != 9 {
		t.Fatalf("%d cells", len(cells))
	}
	home, _ := cell.Of(core.LatLon{LatDeg: 41.715, LonDeg: 44.815}, cell.Level5)
	if _, ok := cells[home]; !ok {
		t.Fatalf("the box's own cell %s is missing", home)
	}
	for _, n := range home.Ring1() {
		if _, ok := cells[n]; !ok {
			t.Fatalf("neighbour %s missing", n)
		}
	}
	_, err = ViewportCells(box, 8)
	var fe *core.FieldError
	if err == nil || !errorsAs(err, &fe) || fe.Field != "bbox" {
		t.Fatalf("over the bound: %v", err)
	}
	// Across the antimeridian: core's cover, both sides.
	cells, err = ViewportCells(geodesy.BBox{MinLat: 0, MinLon: 179.95, MaxLat: 0.05, MaxLon: -179.95}, 100)
	if err != nil || len(cells) == 0 {
		t.Fatalf("antimeridian: %v %d", err, len(cells))
	}
}

// The lab's subscribe examples: each valid one parses, each invalid one
// is refused naming a member (E-01 pair); nothing panics on garbage.
func TestParseSubscribeAgainstTheLabExamples(t *testing.T) {
	for _, ex := range listExamples(t, "console/subscribe/v1/examples") {
		raw := readExample(t, ex)
		validate(t, idSubscribe, raw)
		if _, _, err := ParseSubscribe(raw); err != nil {
			t.Errorf("%s refused: %v", ex, err)
		}
	}
	for _, ex := range listExamples(t, "console/subscribe/v1/examples/invalid") {
		raw := readExample(t, ex)
		if validateErr(idSubscribe, raw) == nil {
			t.Fatalf("%s validates against the lab's schema", ex)
		}
		if _, _, err := ParseSubscribe(raw); err == nil {
			t.Errorf("%s accepted", ex)
		}
	}
	for _, g := range []string{"", "null", "[]", "{}", "1", `{"schema":"console/subscribe/v1"}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,2,3,"x"],"layers":[]}}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,2,3,4],"layers":[1]}}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,50,3,40],"layers":[]}}`,
		`{"schema":"console/subscribe/v1","body":{"bbox":[1,2,3,4],"layers":[]}} {}`,
		`{"schema":"console/status/v1","body":{"bbox":[1,2,3,4],"layers":[]}}`} {
		if _, _, err := ParseSubscribe([]byte(g)); err == nil {
			t.Errorf("%q accepted", g)
		}
	}
}

// fillTracks puts n tracks of one cell into h, captured at at.
func fillTracks(t *testing.T, h *Hub, n int, at time.Time) {
	t.Helper()
	for i := range n {
		h.OfferTrack(trackMsg(t, fmt.Sprintf("trk-%03d", i), baseLatDeg+float64(i%10)*1e-4, baseLonDeg, at, core.IdentRegistered), at)
	}
}

// countTrack reads the frames queued for conn and counts the track
// frames of id.
func countTrack(t *testing.T, conn *fakeConn, id string, wait time.Duration) int {
	t.Helper()
	n := 0
	deadline := time.After(wait)
	for {
		select {
		case raw := <-conn.out:
			f := validateFrame(t, raw)
			if f.Schema == SchemaTrack && trackOf(t, raw).TrackID == id {
				n++
			}
		case <-deadline:
			return n
		}
	}
}

// 05 §3: above 200 tracks in a viewport a track is sent at most at 2 Hz,
// the rest dropped and counted in dropped_frames; at 200 and 199 every
// message goes (E-01 pair at the boundary).
func TestThrottleAt199200And201Tracks(t *testing.T) {
	for _, tc := range []struct {
		tracks    int
		delivered int
	}{{199, 2}, {200, 2}, {201, 1}} {
		t.Run(fmt.Sprint(tc.tracks), func(t *testing.T) {
			h := testHub(t, func(c *Config, _ *Inputs) { c.ThrottleAbove, c.StatusInterval = 200, time.Hour })
			t0 := time.Now()
			fillTracks(t, h, tc.tracks, t0)
			conn := connect(t, h, consoleSession(), nil)
			_, snap := subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
			if len(snap.Tracks) != tc.tracks {
				t.Fatalf("snapshot holds %d tracks", len(snap.Tracks))
			}
			h.OfferTrack(trackMsg(t, "trk-000", baseLatDeg, baseLonDeg, t0.Add(100*time.Millisecond), core.IdentRegistered), t0.Add(100*time.Millisecond))
			h.OfferTrack(trackMsg(t, "trk-000", baseLatDeg, baseLonDeg, t0.Add(200*time.Millisecond), core.IdentRegistered), t0.Add(200*time.Millisecond))
			if got := countTrack(t, conn, "trk-000", 300*time.Millisecond); got != tc.delivered {
				t.Fatalf("%d frames of trk-000, want %d", got, tc.delivered)
			}
			h.Tick(time.Now())
			st := statusOf(t, mustUntil(t, conn, SchemaStatus))
			if want := uint64(2 - tc.delivered); st.DroppedFrames != want || h.Counters().Get(CounterFramesThrottled) != want {
				t.Fatalf("dropped_frames %d, throttled %d, want %d", st.DroppedFrames, h.Counters().Get(CounterFramesThrottled), want)
			}
		})
	}
}

func mustUntil(t *testing.T, conn *fakeConn, schema string) frame {
	t.Helper()
	f, _ := conn.until(t, schema, 2*time.Second)
	return f
}

// The cache ages: a track older than stale_after_s leaves at the tick
// while the bus is connected; with the bus down nothing leaves (E-02:
// the consoles freeze with the age shown). Beside it, a fresh track
// stays.
func TestSnapshotAgeingStopsWhileTheBusIsDown(t *testing.T) {
	var up atomic.Bool
	up.Store(true)
	lost := time.Now().Add(-3 * time.Second)
	h := testHub(t, func(c *Config, in *Inputs) {
		c.StatusInterval = time.Hour
		in.Policy = func() PolicyView {
			return PolicyView{Version: "3", StaleAfterS: 15, LiveMaxAgeS: 10, CISStaleBoundS: 300}
		}
		in.Bus = func() BusView {
			if up.Load() {
				return BusView{Connected: true}
			}
			return BusView{Connected: false, Since: lost}
		}
	})
	now := time.Now()
	h.OfferTrack(trackMsg(t, "old", baseLatDeg, baseLonDeg, now.Add(-20*time.Second), core.IdentRegistered), now)
	h.OfferTrack(trackMsg(t, "fresh", baseLatDeg, baseLonDeg, now.Add(-time.Second), core.IdentRegistered), now)

	up.Store(false)
	h.Tick(now)
	if n, _, _ := h.Sizes(); n != 2 {
		t.Fatalf("bus down: %d tracks held, want both", n)
	}
	conn := connect(t, h, consoleSession(), nil)
	st, snap := subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if st.NATS != NATSUnavailable || st.NATSSince == nil || *st.NATSSince != bus.Stamp(lost) || !has(st.Degraded, DegradedNATS) {
		t.Fatalf("status with the bus down: nats %q since %v degraded %v", st.NATS, st.NATSSince, st.Degraded)
	}
	if len(snap.Tracks) != 2 {
		t.Fatalf("snapshot with the bus down holds %d tracks", len(snap.Tracks))
	}
	for _, tr := range snap.Tracks {
		if b := trackOf(t, tr); b.TrackID == "old" && (b.AgeS == nil || *b.AgeS < 19) {
			t.Fatalf("the old track shows age %v", b.AgeS)
		}
	}

	up.Store(true)
	h.Tick(time.Now())
	if n, _, _ := h.Sizes(); n != 1 || h.Counters().Get(CounterTracksAgedOut) != 1 {
		t.Fatalf("bus up: %d tracks, aged out %d", n, h.Counters().Get(CounterTracksAgedOut))
	}
	st = statusOf(t, mustUntil(t, conn, SchemaStatus))
	if st.NATS != NATSConnected || has(st.Degraded, DegradedNATS) || st.NATSSince != nil {
		t.Fatalf("status with the bus back: %+v", st)
	}
}

// E-10: the track cache at its bound evicts the track updated longest
// ago, counts it and says tracks_evicted; below the bound nothing is
// evicted.
func TestTrackCacheBound(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.MaxTracks, c.StatusInterval = 3, time.Hour })
	now := time.Now()
	for i := range 3 {
		h.OfferTrack(trackMsg(t, fmt.Sprintf("t%d", i), baseLatDeg, baseLonDeg, now, core.IdentRegistered), now)
	}
	if h.Counters().Get(CounterTracksEvicted) != 0 {
		t.Fatal("evicted below the bound")
	}
	conn := connect(t, h, consoleSession(), nil)
	h.Tick(now)
	if st := statusOf(t, mustUntil(t, conn, SchemaStatus)); has(st.Degraded, DegradedTracksEvicted) {
		t.Fatal("tracks_evicted below the bound")
	}
	h.OfferTrack(trackMsg(t, "t3", baseLatDeg, baseLonDeg, now, core.IdentRegistered), now)
	if n, _, _ := h.Sizes(); n != 3 || h.Counters().Get(CounterTracksEvicted) != 1 {
		t.Fatalf("%d tracks, evicted %d", n, h.Counters().Get(CounterTracksEvicted))
	}
	_, snap := subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	for _, tr := range snap.Tracks {
		if trackOf(t, tr).TrackID == "t0" {
			t.Fatal("the track updated longest ago is still held")
		}
	}
	h.Tick(now)
	if st := statusOf(t, mustUntil(t, conn, SchemaStatus)); !has(st.Degraded, DegradedTracksEvicted) {
		t.Fatalf("degraded %v", st.Degraded)
	}
}

// A sample not newer than the one held never moves an aircraft back;
// a newer one replaces it.
func TestOlderSampleIgnoredNewerTaken(t *testing.T) {
	h := testHub(t, nil)
	now := time.Now()
	h.OfferTrack(trackMsg(t, "a", baseLatDeg, baseLonDeg, now, core.IdentRegistered), now)
	h.OfferTrack(trackMsg(t, "a", baseLatDeg+0.01, baseLonDeg, now.Add(-time.Second), core.IdentRegistered), now)
	if h.Counters().Get(CounterTracksOlder) != 1 {
		t.Fatal("older sample not refused")
	}
	h.OfferTrack(trackMsg(t, "a", baseLatDeg+0.02, baseLonDeg, now.Add(time.Second), core.IdentRegistered), now)
	if h.Counters().Get(CounterTracksOlder) != 1 {
		t.Fatal("newer sample refused")
	}
	items := h.tracks.inCells(map[cell.ID]struct{}{mustCell(t, baseLatDeg+0.02, baseLonDeg): {}})
	if len(items) != 1 || items[0].pos.LatDeg != baseLatDeg+0.02 {
		t.Fatalf("held %+v", items)
	}
}

func mustCell(t *testing.T, lat, lon float64) cell.ID {
	t.Helper()
	c, err := cell.Of(core.LatLon{LatDeg: lat, LonDeg: lon}, cell.Level5)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A backlog sample is history and never reaches the live picture; a
// live one does. A malformed message is refused and counted, never a
// panic.
func TestBacklogAndMalformedTracksNeverShown(t *testing.T) {
	h := testHub(t, nil)
	now := time.Now()
	raw := trackMsg(t, "b", baseLatDeg, baseLonDeg, now, core.IdentRegistered)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["backlog"] = true
	backlog, _ := json.Marshal(m)
	h.OfferTrack(backlog, now)
	if n, _, _ := h.Sizes(); n != 0 || h.Counters().Get(CounterTracksBacklog) != 1 {
		t.Fatalf("backlog shown: %d", n)
	}
	h.OfferTrack(raw, now)
	if n, _, _ := h.Sizes(); n != 1 {
		t.Fatal("live sample not shown")
	}
	for _, g := range [][]byte{nil, []byte("{"), []byte(`{"schema":"track/telemetry/v1"}`), []byte(strings.Repeat("x", maxMessageBytes+1))} {
		h.OfferTrack(g, now)
	}
	if h.Counters().Get(CounterTracksMalformed) != 4 {
		t.Fatalf("malformed %d", h.Counters().Get(CounterTracksMalformed))
	}
	sim := trackMsg(t, "s", baseLatDeg, baseLonDeg, now, core.IdentRegistered)
	_ = json.Unmarshal(sim, &m)
	m["body"].(map[string]any)["trust"] = "simulated"
	sim, _ = json.Marshal(m)
	h.OfferTrack(sim, now)
	if h.Counters().Get(CounterTracksMalformed) != 5 {
		t.Fatal("a simulated track reached the picture (06 T11)")
	}
}

// Two consoles with overlapping viewports each receive a track in the
// overlap once; a console whose viewport does not hold it receives none.
func TestOverlappingViewportsReceiveATrackOnceEach(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	a := connect(t, h, consoleSession(), nil)
	b := connect(t, h, consoleSession(), nil)
	far := connect(t, h, consoleSession(), nil)
	subscribe(t, a, subscribeFrameOf(44.78, 41.69, 44.84, 41.73))
	subscribe(t, b, subscribeFrameOf(44.81, 41.70, 44.88, 41.75))
	subscribe(t, far, subscribeFrameOf(41.60, 41.60, 41.70, 41.70))
	now := time.Now()
	h.OfferTrack(trackMsg(t, "x", baseLatDeg, baseLonDeg, now, core.IdentRegistered), now)
	for name, c := range map[string]*fakeConn{"a": a, "b": b} {
		if n := countTrack(t, c, "x", 200*time.Millisecond); n != 1 {
			t.Fatalf("%s received %d frames", name, n)
		}
	}
	if n := countTrack(t, far, "x", 100*time.Millisecond); n != 0 {
		t.Fatalf("the far console received %d frames", n)
	}
}

// Moving the viewport away stops the stream of the old cells and the
// new snapshot replaces the old (the console replaces, never merges).
func TestResubscribeMovesTheStream(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	conn := connect(t, h, consoleSession(), nil)
	subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	_, snap := subscribe(t, conn, subscribeFrameOf(41.60, 41.60, 41.70, 41.70))
	if len(snap.Tracks) != 0 {
		t.Fatal("snapshot of the new viewport holds tracks")
	}
	now := time.Now()
	h.OfferTrack(trackMsg(t, "x", baseLatDeg, baseLonDeg, now, core.IdentRegistered), now)
	if n := countTrack(t, conn, "x", 100*time.Millisecond); n != 0 {
		t.Fatal("a track of the old viewport was sent")
	}
}

// C-08: a violation raised before the console connected is in its
// snapshot; its clear is forwarded and the next snapshot does not hold
// it; a raise read back after the clear does not revive it.
func TestActiveViolationReplayedToALateConsole(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	now := time.Now()
	id := bus.NewULID(now)
	raise := violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateRaised, now)
	h.OfferViolation(raise, now)
	h.OfferViolation(violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateUpdated, now.Add(time.Second)), now.Add(time.Second))
	conn := connect(t, h, consoleSession(), nil)
	_, snap := subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if len(snap.Alerts) != 1 {
		t.Fatalf("snapshot alerts %d", len(snap.Alerts))
	}
	// Without the alerts layer the same viewport holds none.
	_, snap = subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73, LayerTracks))
	if len(snap.Alerts) != 0 {
		t.Fatal("alerts without the layer")
	}
	subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	h.OfferViolation(violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateCleared, now.Add(2*time.Second)), now.Add(2*time.Second))
	f, raw := conn.until(t, SchemaViolation, time.Second)
	var v violation.Message
	if err := json.Unmarshal(raw, &v); err != nil || v.Body.State != violation.StateCleared || f.Producer != violation.Producer {
		t.Fatalf("forwarded %s", raw)
	}
	h.OfferViolation(raise, now.Add(3*time.Second))
	if h.Counters().Get(CounterAlertsAfterClear) != 1 {
		t.Fatal("a raise read back after the clear was not ignored")
	}
	_, snap = subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if len(snap.Alerts) != 0 {
		t.Fatal("cleared violation still in the snapshot")
	}
}

// A violation detect stopped republishing is unconfirmed past
// silentAfter (said) and forgotten past forgetAfter (counted); a
// republish brings it back. With the bus down nothing is forgotten.
func TestSilentViolationUnconfirmedThenForgottenThenRevived(t *testing.T) {
	s := newAlertSet(10, 10, 5*time.Second, 20*time.Second)
	now := time.Now()
	id := bus.NewULID(now)
	m, _ := violation.Decode(violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateRaised, now))
	c5 := mustCell(t, baseLatDeg, baseLonDeg)
	s.offer(m, nil, c5, now)
	if f, u, _ := s.age(now.Add(4 * time.Second)); f != 0 || u != 0 {
		t.Fatalf("young: forgotten %d unconfirmed %d", f, u)
	}
	f, u, since := s.age(now.Add(6 * time.Second))
	if f != 0 || u != 1 || !since.Equal(now.Add(5*time.Second)) {
		t.Fatalf("silent: forgotten %d unconfirmed %d since %v", f, u, since)
	}
	if f, _, _ := s.ageNoForget(now.Add(time.Hour)); f != 0 || s.len() != 1 {
		t.Fatal("forgotten with the bus down")
	}
	if f, _, _ := s.age(now.Add(21 * time.Second)); f != 1 || s.len() != 0 {
		t.Fatalf("forgotten %d len %d", f, s.len())
	}
	up, _ := violation.Decode(violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateUpdated, now.Add(22*time.Second)))
	if v, _ := s.offer(up, nil, c5, now.Add(22*time.Second)); v != alertForward || s.len() != 1 {
		t.Fatal("a republish did not revive the violation")
	}
}

// E-10: the active set at its bound evicts the one heard longest ago;
// below it nothing.
func TestAlertSetBound(t *testing.T) {
	s := newAlertSet(2, 2, 5*time.Second, 20*time.Second)
	now := time.Now()
	c5 := mustCell(t, baseLatDeg, baseLonDeg)
	var ids []string
	for i := range 3 {
		id := bus.NewULID(now.Add(time.Duration(i) * time.Millisecond))
		ids = append(ids, id)
		m, _ := violation.Decode(violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateRaised, now))
		_, ev := s.offer(m, nil, c5, now.Add(time.Duration(i)*time.Second))
		if ev != (i == 2) {
			t.Fatalf("offer %d evicted %v", i, ev)
		}
	}
	if _, ok := s.byID[ids[0]]; ok || s.len() != 2 {
		t.Fatal("the oldest is still held")
	}
	// The cleared memory is bounded too.
	for i := range 5 {
		id := bus.NewULID(now.Add(time.Duration(10+i) * time.Millisecond))
		m, _ := violation.Decode(violationMsg(t, id, baseLatDeg, baseLonDeg, violation.StateCleared, now))
		s.offer(m, nil, c5, now)
	}
	if len(s.cleared) != 2 || s.clearedLRU.Len() != 2 {
		t.Fatalf("cleared memory %d", len(s.cleared))
	}
}

// 06 §5: a Display Provider flight's operator position is shown to the
// console realm and omitted for the police realm (any non-console realm,
// any public subset). E-01 pair.
func TestOperatorPositionForTheConsoleRealmOnly(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	console := connect(t, h, consoleSession(), nil)
	police := connect(t, h, Session{Subject: "p", JTI: "p", Realm: RealmPolice}, nil)
	for _, c := range []*fakeConn{console, police} {
		subscribe(t, c, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	}
	now := time.Now()
	raw := trackMsgWith(t, "dp-1", baseLatDeg, baseLonDeg, now, core.IdentRegistered, &track.Position{Lat: 41.70, Lng: 44.80})
	h.OfferTrack(raw, now)
	_, cf := console.until(t, SchemaTrack, time.Second)
	_, pf := police.until(t, SchemaTrack, time.Second)
	if op := trackOf(t, cf).OperatorPosition; op == nil || op.Lat != 41.70 {
		t.Fatalf("console: operator position %v", op)
	}
	if strings.Contains(string(pf), "operator_position") {
		t.Fatalf("police frame carries the operator position: %s", pf)
	}
	_, snap := subscribe(t, police, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if strings.Contains(string(snap.Tracks[0]), "operator_position") {
		t.Fatal("police snapshot carries the operator position")
	}
}

// T6: no frame type has a name, address or contact member. The check is
// over the JSON names of every type a frame is made of.
func TestFramesCarryNoPersonalDataMembers(t *testing.T) {
	forbidden := []string{"name", "first_name", "last_name", "full_name", "address", "email", "phone", "contact",
		"birth", "date_of_birth", "national_id", "person", "pilot_name", "operator_name"}
	var names []string
	for _, v := range []any{StatusBody{}, SnapshotBody{}, SourceState{}, trackOutBody{}, sourcesBody{}} {
		names = append(names, jsonNames(fmt.Sprintf("%T", v), v)...)
	}
	if len(names) < 40 {
		t.Fatalf("only %d member names walked: %v", len(names), names)
	}
	for _, n := range names {
		for _, f := range forbidden {
			if strings.EqualFold(n[strings.LastIndex(n, ".")+1:], f) {
				t.Errorf("%s is a personal-data member", n)
			}
		}
	}
	// The check catches one (E-01).
	type withPII struct {
		Email string `json:"email"`
	}
	if got := jsonNames("x", withPII{}); len(got) != 1 || !strings.HasSuffix(got[0], "email") {
		t.Fatalf("walker missed a member: %v", got)
	}

	// The EU registration secret (G-04) is in no frame of any realm: of
	// operator_reg and registered_operator_reg only regnum.PublicPart
	// leaves, live and in the snapshot. A number without a secret part is
	// forwarded as broadcast (the pair).
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	console := connect(t, h, consoleSession(), nil)
	police := connect(t, h, Session{Subject: "p-1", JTI: "j-2", Realm: RealmPolice, Roles: []string{"police"}}, nil)
	for _, c := range []*fakeConn{console, police} {
		subscribe(t, c, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	}
	now := time.Now()
	withReg := func(id, reg, registered string) []byte {
		var m map[string]any
		if err := json.Unmarshal(trackMsg(t, id, baseLatDeg, baseLonDeg, now, core.IdentUnknownOperator), &m); err != nil {
			t.Fatal(err)
		}
		ident := m["body"].(map[string]any)["identification"].(map[string]any)
		ident["operator_reg"], ident["registered_operator_reg"] = reg, registered
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	h.OfferTrack(withReg("suffixed", "FIN87astrdge12k8-xyz", "GEOabcd1234efgh-q7w"), now)
	h.OfferTrack(withReg("plain", "FIN87astrdge12k8", "GEOabcd1234efgh"), now)
	want := map[string][2]string{"suffixed": {"FIN87astrdge12k8", "GEOabcd1234efgh"}, "plain": {"FIN87astrdge12k8", "GEOabcd1234efgh"}}
	checkRegs := func(where string, raw []byte) {
		t.Helper()
		for _, secret := range []string{"xyz", "q7w"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("%s carries the registration secret %q: %s", where, secret, raw)
			}
		}
		var f struct {
			Body struct {
				TrackID        string `json:"track_id"`
				Identification struct {
					OperatorReg           *string `json:"operator_reg"`
					RegisteredOperatorReg *string `json:"registered_operator_reg"`
				} `json:"identification"`
			} `json:"body"`
		}
		if err := json.Unmarshal(raw, &f); err != nil {
			t.Fatal(err)
		}
		w := want[f.Body.TrackID]
		id := f.Body.Identification
		if id.OperatorReg == nil || *id.OperatorReg != w[0] || id.RegisteredOperatorReg == nil || *id.RegisteredOperatorReg != w[1] {
			t.Fatalf("%s %s: operator_reg %v registered %v, want %v", where, f.Body.TrackID, id.OperatorReg, id.RegisteredOperatorReg, w)
		}
	}
	for name, c := range map[string]*fakeConn{"console": console, "police": police} {
		for range 2 {
			_, raw := c.until(t, SchemaTrack, 2*time.Second)
			checkRegs(name+" live", raw)
		}
		_, snap := subscribe(t, c, subscribeFrameOf(44.80, 41.70, 44.86, 41.73))
		if len(snap.Tracks) != 2 {
			t.Fatalf("%s snapshot holds %d tracks", name, len(snap.Tracks))
		}
		for _, tr := range snap.Tracks {
			checkRegs(name+" snapshot", tr)
		}
	}
}

// TestStatusFrameCarriesThePolicyAndTheExtras: the thresholds and the
// policy version are the active policy's (INV-03); the projection ages
// and versions are the reader's; without a policy the documented
// defaults are shown and the frame says policy_default.
func TestStatusFrameCarriesThePolicyAndTheExtras(t *testing.T) {
	var defaulted atomic.Bool
	h := testHub(t, func(c *Config, in *Inputs) {
		c.StatusInterval = time.Hour
		in.Policy = func() PolicyView {
			if defaulted.Load() {
				return PolicyView{Version: "0", StaleAfterS: 15, LiveMaxAgeS: 10, CISStaleBoundS: 300, Default: true}
			}
			return PolicyView{Version: "7", StaleAfterS: 12, LiveMaxAgeS: 4, CISStaleBoundS: 300}
		}
		in.Projections = func(time.Time) ProjectionView {
			return ProjectionView{Read: true, RegistryAgeS: f64(1.5), CISVersion: ptr("42"), CISAgeS: f64(301), ZonesVersion: ptr("9")}
		}
	})
	conn := connect(t, h, consoleSession(), nil)
	st, snap := subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if st.PolicyVersion != "7" || st.StaleAfterS != 12 || st.LiveMaxAgeS != 4 {
		t.Fatalf("policy %q %v %v", st.PolicyVersion, st.StaleAfterS, st.LiveMaxAgeS)
	}
	if st.ProjectionAgeS == nil || *st.ProjectionAgeS != 1.5 || st.CISVersion == nil || *st.CISVersion != "42" || !has(st.Degraded, DegradedCISStale) {
		t.Fatalf("extras %+v", st)
	}
	if has(st.Degraded, DegradedPolicyDefault) || snap.ZonesVersion == nil || *snap.ZonesVersion != "9" {
		t.Fatalf("degraded %v zones %v", st.Degraded, snap.ZonesVersion)
	}
	if st.DPState != DPUnavailable || !has(st.Degraded, DegradedDP) {
		t.Fatalf("dp_state %q", st.DPState)
	}
	for _, slug := range st.Degraded {
		if st.DegradedSince[slug] == "" {
			t.Fatalf("%s without since", slug)
		}
	}
	defaulted.Store(true)
	h.Tick(time.Now())
	if st = statusOf(t, mustUntil(t, conn, SchemaStatus)); st.PolicyVersion != "0" || !has(st.Degraded, DegradedPolicyDefault) {
		t.Fatalf("default policy not said: %+v", st)
	}
}

// A console without a subscription is told so, not shown an empty sky
// (E-02); once subscribed the slug is gone.
func TestNoSubscriptionIsSaid(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	conn := connect(t, h, consoleSession(), nil)
	h.Tick(time.Now())
	if st := statusOf(t, mustUntil(t, conn, SchemaStatus)); !has(st.Degraded, DegradedNoSubscription) {
		t.Fatalf("degraded %v", st.Degraded)
	}
	st, _ := subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if has(st.Degraded, DegradedNoSubscription) {
		t.Fatal("no_subscription after subscribing")
	}
}

// A viewport over PICTURE_MAX_CELLS keeps the previous one and says
// viewport_too_large; the stream of the previous one goes on. Beside it,
// a viewport at the bound is taken.
func TestViewportTooLargeKeepsThePreviousOne(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.MaxCells = time.Hour, 50 })
	conn := connect(t, h, consoleSession(), nil)
	subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	conn.in <- subscribeFrameOf(40, 40, 46, 44)
	st := statusOf(t, mustUntil(t, conn, SchemaStatus))
	if !has(st.Degraded, DegradedViewportTooLarge) || h.Counters().Get(CounterSubscribeTooLarge) != 1 {
		t.Fatalf("degraded %v", st.Degraded)
	}
	now := time.Now()
	h.OfferTrack(trackMsg(t, "x", baseLatDeg, baseLonDeg, now, core.IdentRegistered), now)
	if n := countTrack(t, conn, "x", 200*time.Millisecond); n != 1 {
		t.Fatalf("previous viewport's stream: %d frames", n)
	}
	st, _ = subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if has(st.Degraded, DegradedViewportTooLarge) {
		t.Fatal("viewport_too_large after an accepted viewport")
	}
}

// A frame that is not a console/subscribe/v1 closes the connection with
// 1007 naming the member; a valid one keeps it open.
func TestInvalidFrameClosesWith1007(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	conn := connect(t, h, consoleSession(), nil)
	subscribe(t, conn, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if _, _, closed := conn.closeCode(); closed {
		t.Fatal("closed after a valid frame")
	}
	conn.in <- []byte(`{"schema":"console/subscribe/v1","body":{"bbox":[1,2,3],"layers":[]}}`)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if code, reason, closed := conn.closeCode(); closed {
			if code != CloseInvalid || !strings.Contains(reason, "bbox") {
				t.Fatalf("closed %d %q", code, reason)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("not closed")
}

// 05 §5: under a flood a console that reads slowly loses frames, counted
// in its dropped_frames, and stays connected; its status still arrives.
func TestFloodDropsFramesAndTheConsoleStays(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.SendBuffer = time.Hour, 8 })
	conn := newFakeConn(1)
	if !h.Reserve() {
		t.Fatal("full")
	}
	go h.Serve(conn, consoleSession(), "t", nil)
	reader := make(chan frame, 1<<16)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case raw := <-conn.out:
				time.Sleep(time.Millisecond) // a console that keeps up at about 1000 frames/s
				reader <- decodeFrame(t, raw)
			}
		}
	}()
	defer close(stop)
	conn.in <- subscribeFrameOf(44.80, 41.70, 44.85, 41.73)
	time.Sleep(100 * time.Millisecond)
	now := time.Now()
	for i := range 5000 {
		at := now.Add(time.Duration(i) * time.Millisecond)
		h.OfferTrack(trackMsg(t, fmt.Sprintf("f%02d", i%50), baseLatDeg, baseLonDeg, at, core.IdentRegistered), at)
	}
	h.Tick(time.Now())
	deadline := time.After(5 * time.Second)
	for {
		select {
		case f := <-reader:
			if f.Schema != SchemaStatus {
				continue
			}
			var st StatusBody
			_ = json.Unmarshal(f.Body, &st)
			if st.DroppedFrames == 0 {
				continue
			}
			if _, _, closed := conn.closeCode(); closed {
				t.Fatal("the console was closed")
			}
			if h.Counters().Get(CounterFramesQueueFull) == 0 {
				t.Fatal("no queue-full drop counted")
			}
			t.Logf("dropped_frames %d of 5000", st.DroppedFrames)
			return
		case <-deadline:
			t.Fatal("no status with dropped_frames")
		}
	}
}

// Manned traffic is stored by subject and forwarded as received to the
// consoles with the manned layer; without it nothing; a subject that is
// not man.v1.<cell3>.<cell5>.<icao24> is refused.
func TestMannedForwardedByLayer(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval = time.Hour })
	with := connect(t, h, consoleSession(), nil)
	without := connect(t, h, consoleSession(), nil)
	subscribe(t, with, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	subscribe(t, without, subscribeFrameOf(44.80, 41.70, 44.85, 41.73, LayerTracks))
	c3, c5, err := cell.Tokens(core.LatLon{LatDeg: baseLatDeg, LonDeg: baseLonDeg})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	env := bus.SystemEnvelope(SchemaManned, "ansp/manned-feed", now, map[string]any{"icao24": "4ca123"})
	raw, _ := json.Marshal(env)
	h.OfferManned(fmt.Sprintf("man.v1.%s.%s.4ca123", c3, c5), raw)
	if f, _ := with.until(t, SchemaManned, time.Second); f.Producer != "ansp/manned-feed" {
		t.Fatalf("producer %q", f.Producer)
	}
	select {
	case got := <-without.out:
		if decodeFrame(t, got).Schema == SchemaManned {
			t.Fatal("manned sent without the layer")
		}
	case <-time.After(100 * time.Millisecond):
	}
	h.OfferManned("man.v1.x", raw)
	h.OfferManned(fmt.Sprintf("man.v1.%s.%s.a.b", c3, c5), raw)
	if h.Counters().Get(CounterMannedMalformed) != 2 {
		t.Fatalf("malformed %d", h.Counters().Get(CounterMannedMalformed))
	}
	_, snap := subscribe(t, with, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	if len(snap.Manned) != 1 {
		t.Fatalf("snapshot manned %d", len(snap.Manned))
	}
}
