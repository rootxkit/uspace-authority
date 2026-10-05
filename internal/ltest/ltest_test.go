package ltest

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/odid"

	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The harness tests itself (WP-25): what the simulated receiver sends
// decodes to the path it was given, the fake Service Provider answers in
// F3411's shapes, the runner detects a miss and a false alert, and every
// bound of the harness holds when exceeded. None needs the stack.

// testReceiver is a Receiver without a stack, for its encoder.
func testReceiver(t *testing.T) *Receiver {
	t.Helper()
	g, err := geoid.Load(GeoidFile())
	if err != nil {
		t.Fatal(err)
	}
	return &Receiver{ID: "rx-self", LatDeg: 41.70, LonDeg: 44.80, n: g}
}

// The simulated receiver's frames decode, through uspace-core's own
// decoder, to the path it was given: position to the wire's 1e-7 deg,
// HAE = AMSL + N of the test geoid (15.9 m, R-16) to the 0.5 m step,
// speed, track, status, the broadcast time in tenths, the serial and
// the operator number; a transmitter that does not know UTC yet sends no
// timestamp; Bluetooth 4 datagrams carry one message each, the Basic ID
// every third step.
func TestReceiverFramesDecodeToThePathGiven(t *testing.T) {
	r := testReceiver(t)
	legs := []Leg{Stay(2, At(41.7151, 44.8271, 520)), Move(4, At(41.7151, 44.8271, 520), At(41.7171, 44.8291, 560)), Landed(1, At(41.7171, 44.8291, 430))}
	a := &Aircraft{Transmitter: "AA:BB:CC:25:00:01", Serial: "TESTSELF0001", OperatorID: "GEOTEST00009901", System: true, UTCFromStep: 1,
		Path: Legs(legs...)}
	heard := time.Date(2026, 10, 5, 9, 15, 7, 340_000_000, time.UTC)
	for step := range Steps(legs...) {
		want := a.Path(step)
		msgs, err := r.Messages(a, step, heard)
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		pack, err := odid.EncodePack(msgs)
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		got, err := odid.Decode(pack, odid.DecodeOptions{})
		if err != nil {
			t.Fatalf("step %d: decode: %v", step, err)
		}
		var types []odid.MessageType
		for _, m := range got {
			types = append(types, m.Type())
			switch m := m.(type) {
			case odid.BasicID:
				if m.IDType != odid.IDTypeSerial || m.UAID != a.Serial {
					t.Errorf("step %d: basic ID %+v", step, m)
				}
			case odid.OperatorID:
				if m.OperatorID != a.OperatorID {
					t.Errorf("step %d: operator ID %+v", step, m)
				}
			case odid.Location:
				if m.LatDeg == nil || m.LonDeg == nil || math.Abs(*m.LatDeg-want.LatDeg) > 1e-7 || math.Abs(*m.LonDeg-want.LonDeg) > 1e-7 {
					t.Errorf("step %d: position %v,%v want %v,%v", step, m.LatDeg, m.LonDeg, want.LatDeg, want.LonDeg)
				}
				if m.AltHAEM == nil || math.Abs(*m.AltHAEM-(want.AltAMSLM+15.9)) > 0.5 {
					t.Errorf("step %d: HAE %v, want AMSL %v + 15.9", step, m.AltHAEM, want.AltAMSLM)
				}
				if m.Status != want.Status {
					t.Errorf("step %d: status %v want %v", step, m.Status, want.Status)
				}
				if m.SpeedHorizontalMS == nil || math.Abs(*m.SpeedHorizontalMS-want.SpeedMS) > 0.75 {
					t.Errorf("step %d: speed %v want %v", step, m.SpeedHorizontalMS, want.SpeedMS)
				}
				if want.SpeedMS > 0 && (m.DirectionDeg == nil || math.Abs(*m.DirectionDeg-want.TrackDeg) > 1) {
					t.Errorf("step %d: track %v want %v", step, m.DirectionDeg, want.TrackDeg)
				}
				switch {
				case step < a.UTCFromStep && m.SecondsAfterHour != nil:
					t.Errorf("step %d: a timestamp before the transmitter knows UTC", step)
				case step >= a.UTCFromStep && (m.SecondsAfterHour == nil || math.Abs(*m.SecondsAfterHour-907.3) > 1e-9):
					t.Errorf("step %d: seconds after the hour %v, want 907.3", step, m.SecondsAfterHour)
				}
			case odid.System:
				if m.OperatorLatDeg == nil || math.Abs(*m.OperatorLatDeg-r.LatDeg) > 1e-7 {
					t.Errorf("step %d: system %+v", step, m)
				}
			}
		}
		if !slices.Equal(types, []odid.MessageType{odid.TypeBasicID, odid.TypeLocation, odid.TypeSystem, odid.TypeOperatorID}) {
			t.Errorf("step %d: messages %v", step, types)
		}
	}

	bt := &Aircraft{Transmitter: "AA:BB:CC:25:00:02", Serial: "TESTSELF0002", OnePerDatagram: true, BasicIDEvery: 3, Path: Hold(41.7, 44.8, 500)}
	for step := range 6 {
		r.mu.Lock()
		obs, err := r.observations(bt, step, heard)
		r.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if step%3 == 0 {
			want = 2
		}
		if len(obs) != want {
			t.Fatalf("step %d: %d datagrams, want %d", step, len(obs), want)
		}
		for _, o := range obs {
			raw, err := hex.DecodeString(o.PayloadHex)
			if err != nil || len(raw) != odid.MessageSize {
				t.Fatalf("step %d: datagram of %d bytes", step, len(raw))
			}
			if _, err := odid.Decode(raw, odid.DecodeOptions{}); err != nil {
				t.Fatalf("step %d: %v", step, err)
			}
		}
	}
}

// The drop rate and an exact drop are accounted for: every observation
// built is sent or dropped, and the tally balances.
func TestReceiverDropsAreCountedAndTheTallyBalances(t *testing.T) {
	r := testReceiver(t)
	r.DropRate, r.Seed = 0.3, 7
	r.Drop = func(step int, _ *Aircraft, typ odid.MessageType) bool { return step == 4 && typ == odid.TypeBasicID }
	a := &Aircraft{Transmitter: "AA:BB:CC:25:00:03", Serial: "TESTSELF0003", OnePerDatagram: true, Path: Hold(41.7, 44.8, 500)}
	kept := 0
	for step := range 50 {
		r.mu.Lock()
		obs, err := r.observations(a, step, time.Now())
		r.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		kept += len(obs)
	}
	tl := r.Tally()
	if tl.Sent != 100 || tl.Dropped == 0 || tl.Dropped+kept != tl.Sent {
		t.Fatalf("tally %+v, kept %d", tl, kept)
	}
	tl.Accepted = kept
	if !tl.Balanced() {
		t.Fatalf("not balanced: %+v", tl)
	}
	tl.Accepted--
	if tl.Balanced() {
		t.Fatal("an observation unaccounted for balanced")
	}
}

// The fake Service Provider answers GET /uss/flights?view= and the
// details in F3411's shapes: its bodies unmarshal through uspace-core
// f3411 into the flights it was given.
func TestFakeServiceProviderAnswersInF3411Shapes(t *testing.T) {
	sp := fakedss.NewSP()
	defer sp.Close()
	f := SPFlight{ID: "fl-self", Serial: "TEST9SELF0001", OperatorID: "GEOTEST00009901",
		At: func(time.Time) (float64, float64, float64) { return 41.70, 44.80, 535.9 }}
	now := time.Now()
	serial, op := f.Serial, f.OperatorID
	sp.SetFlights([]f3411.RIDFlight{f.RIDFlight(now)},
		map[string]f3411.RIDFlightDetails{f.ID: {Id: f.ID, UasId: &f3411.UASID{SerialNumber: &serial}, OperatorId: &op}})
	view := dp.ViewParam(dp.Box{MinLat: 41.69, MinLon: 44.79, MaxLat: 41.71, MaxLon: 44.81})
	get := func(path string, v any) {
		t.Helper()
		resp, err := http.Get(sp.URL() + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		dec := json.NewDecoder(resp.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(v); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	var flights f3411.GetFlightsResponse
	get("/uss/flights?view="+view, &flights)
	if flights.Flights == nil || len(*flights.Flights) != 1 {
		t.Fatalf("flights %+v", flights)
	}
	got := (*flights.Flights)[0]
	p := got.CurrentState.Position
	if got.Id != f.ID || *p.Lat != 41.70 || *p.Lng != 44.80 || math.Abs(float64(*p.Alt)-535.9) > 0.01 ||
		*got.CurrentState.OperationalStatus != f3411.Airborne {
		t.Fatalf("flight %+v", got)
	}
	var details f3411.GetFlightDetailsResponse
	get("/uss/flights/"+f.ID+"/details", &details)
	if details.Details.UasId == nil || *details.Details.UasId.SerialNumber != f.Serial || *details.Details.OperatorId != f.OperatorID {
		t.Fatalf("details %+v", details)
	}
	// Outside the view: no flight (the absence beside the presence).
	var none f3411.GetFlightsResponse
	get("/uss/flights?view="+dp.ViewParam(dp.Box{MinLat: 41.50, MinLon: 44.50, MaxLat: 41.51, MaxLon: 44.51}), &none)
	if none.Flights == nil || len(*none.Flights) != 0 {
		t.Fatalf("a flight outside the view: %+v", none)
	}
}

func seen(id string, kind violation.Kind, track, clearReason string) *Violation {
	v := &Violation{ID: id, Kind: kind, Track: track, Raised: true, RaisedAt: time.Unix(100, 0), RaiseCapturedAt: time.Unix(99, 0),
		Severity: string(core.SeverityCritical)}
	if clearReason != "" {
		v.ClearedAt, v.ClearReason = time.Unix(110, 0), clearReason
	}
	return v
}

// E-01: the runner detects a miss, a false alert, a wrong clear, an
// open violation expected cleared and a wrong severity, and passes the
// run that matches; the latency is captured_at to the raise.
func TestJudgeDetectsMissesFalseAlertsAndWrongClears(t *testing.T) {
	run := []*Violation{seen("V1", violation.KindZoneIncursion, "T1", "resolved"), seen("V2", violation.KindUnregistered, "T2", "resolved")}
	match := []Expect{Raise(violation.KindZoneIncursion, "T1", "resolved"), Raise(violation.KindUnregistered, "T2", "resolved").WithSeverity(core.SeverityCritical)}
	if rep := Judge(run, match); len(rep.Failures) != 0 || rep.MissedAlerts != 0 || rep.FalseAlerts != 0 || rep.Latency.N != 2 || rep.Latency.Max != 1000 {
		t.Fatalf("a matching run: %+v", rep)
	}
	cases := map[string]struct {
		expects      []Expect
		missed, fals int
		phrase       string
	}{
		"a raise that never came":  {append(slices.Clone(match), Raise(violation.KindHeight120m, "T1", "resolved")), 1, 0, "missed: height_120m"},
		"a second raise expected":  {[]Expect{Raise(violation.KindZoneIncursion, "T1", "resolved", "resolved"), match[1]}, 1, 0, "raise 2 of 2 never came"},
		"an alert nothing expects": {match[:1], 0, 1, "false alert: V2 unregistered"},
		"the wrong clear":          {[]Expect{Raise(violation.KindZoneIncursion, "T1", "stale"), match[1]}, 0, 0, "cleared resolved, expected stale"},
		"open expected, cleared":   {[]Expect{Raise(violation.KindZoneIncursion, "T1", ""), match[1]}, 0, 0, "expected still open"},
		"the wrong severity":       {[]Expect{match[0], match[1].WithSeverity(core.SeverityWarning)}, 0, 0, "severity critical, expected warning"},
		"the wrong zone":           {[]Expect{match[0].InZone("GEO/OTHER"), match[1]}, 1, 1, "missed: zone_incursion on T1 in GEO/OTHER"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rep := Judge(run, c.expects)
			if rep.MissedAlerts != c.missed || rep.FalseAlerts != c.fals || !strings.Contains(strings.Join(rep.Failures, "\n"), c.phrase) {
				t.Fatalf("missed %d false %d failures %q; want %d, %d and %q", rep.MissedAlerts, rep.FalseAlerts, rep.Failures, c.missed, c.fals, c.phrase)
			}
		})
	}
	slow := seen("V5", violation.KindZoneIncursion, "T5", "resolved")
	slow.RaisedAt = slow.RaiseCapturedAt.Add(RaiseLatencyBudget)
	if rep := Judge([]*Violation{slow}, []Expect{Raise(violation.KindZoneIncursion, "T5", "resolved")}); !strings.Contains(strings.Join(rep.Failures, " "), "over the 2000 ms budget") {
		t.Fatalf("a raise at the budget passed: %+v", rep.Failures)
	}
	if rep := Judge([]*Violation{slow}, []Expect{Raise(violation.KindZoneIncursion, "T5", "resolved").GatedByAnOutcome()}); len(rep.Failures) != 0 {
		t.Fatalf("a gated raise was held to the budget: %+v", rep.Failures)
	}
	open := []*Violation{seen("V3", violation.KindZoneIncursion, "T3", "")}
	if rep := Judge(open, []Expect{Raise(violation.KindZoneIncursion, "T3", "resolved")}); !strings.Contains(strings.Join(rep.Failures, " "), "never cleared") {
		t.Fatalf("an open violation expected cleared: %+v", rep.Failures)
	}
	if rep := Judge(open, []Expect{Raise(violation.KindZoneIncursion, "T3", "")}); len(rep.Failures) != 0 {
		t.Fatalf("an open violation expected open: %+v", rep.Failures)
	}
	notRaised := &Violation{ID: "V4", Kind: violation.KindZoneIncursion, Track: "T4", ClearedAt: time.Unix(1, 0), ClearReason: "resolved"}
	if rep := Judge([]*Violation{notRaised}, []Expect{Raise(violation.KindZoneIncursion, "T4", "resolved")}); !strings.Contains(strings.Join(rep.Failures, " "), "not a raise") {
		t.Fatalf("a clear without its raise: %+v", rep.Failures)
	}
}

func TestDistribute(t *testing.T) {
	if d := Distribute(nil); d.N != 0 {
		t.Fatalf("%+v", d)
	}
	xs := make([]float64, 0, 100)
	for i := 100; i >= 1; i-- {
		xs = append(xs, float64(i))
	}
	d := Distribute(xs)
	if d.N != 100 || d.Min != 1 || d.P50 != 50 || d.P95 != 95 || d.P99 != 99 || d.Max != 100 || xs[0] != 100 {
		t.Fatalf("%+v (input reordered: %v)", d, xs[0] != 100)
	}
}

// E-10: the log lines a process keeps are bounded; past the bound the
// oldest go and are counted, and a waiter sees a line written after it
// started waiting without polling.
func TestLinesAreBoundedAndWake(t *testing.T) {
	l := NewLines(3)
	for i := range 5 {
		fmt.Fprintf(l, `{"msg":"m%d","n":%d}`+"\n", i, i)
	}
	if l.Dropped() != 2 || l.Find("m0", nil) != nil || l.Find("m4", nil) == nil || len(l.All("m3")) != 1 {
		t.Fatalf("dropped %d, tail %q", l.Dropped(), l.Tail(10))
	}
	fmt.Fprint(l, "not json\npartial")
	if m := l.Find("not json", nil); m == nil || m["unparsed"] != true {
		t.Fatalf("an unparsed line %v", m)
	}
	if l.Find("partial", nil) != nil {
		t.Fatal("a line without its newline was read")
	}
	fmt.Fprintln(l)
	if l.Find("partial", nil) == nil {
		t.Fatal("the partial line, completed, was not read")
	}
	done := make(chan map[string]any, 1)
	go func() { done <- l.Wait("late", nil, 10*time.Second) }()
	fmt.Fprintln(l, `{"msg":"late"}`)
	if m := <-done; m == nil {
		t.Fatal("the waiter missed the line")
	}
	if l.Wait("never", nil, 10*time.Millisecond) != nil {
		t.Fatal("a line that was never written was found")
	}
}

// E-10: each list the recorder keeps is bounded the same way.
func TestRecorderListsAreBounded(t *testing.T) {
	var dropped int
	var xs []int
	for i := range 5 {
		xs = bounded(xs, i, 3, &dropped)
	}
	if !slices.Equal(xs, []int{2, 3, 4}) || dropped != 2 {
		t.Fatalf("%v dropped %d", xs, dropped)
	}
}

// Fixtures name test identities only (CLAUDE.md rule 11), and every
// zone a scenario can build parses through uspace-core's ED-318 reader.
func TestZoneFeaturesParseAndTheSpellingIsED318s(t *testing.T) {
	for _, typ := range []string{"PROHIBITED", "REQ_AUTHORIZATION", "CONDITIONAL", "USPACE"} {
		z := Zone{ID: "SELF1", Type: typ, LatDeg: 41.7, LonDeg: 44.8, HalfSideDeg: 0.001, LowerM: 0, UpperM: 120, LowerRef: "AGL", UpperRef: "AGL"}
		if _, err := z.Feature(); err != nil {
			t.Errorf("%s: %v", typ, err)
		}
	}
	// ED-269's spelling is refused, naming the field (the absence beside
	// the presence above).
	if _, err := (Zone{ID: "SELF2", Type: "REQ_AUTHORISATION", LatDeg: 41.7, LonDeg: 44.8, HalfSideDeg: 0.001, UpperM: 100}).Feature(); err == nil {
		t.Error("the ED-269 spelling was taken as ED-318")
	}
}

func TestReceiverIDsAreValidReceiverIDs(t *testing.T) {
	s := &Stack{unique: "smoke_r_1791158890321713600_1"}
	for _, prefix := range []string{"rx-smoke", "RX_With Spaces", strings.Repeat("x", 80)} {
		id := s.ReceiverID(prefix)
		if len(id) > 63 || id != strings.ToLower(id) || strings.ContainsAny(id, "_ ") || strings.HasPrefix(id, "-") {
			t.Errorf("%q -> %q", prefix, id)
		}
	}
}

func TestHostURLNamesAHost(t *testing.T) {
	if got := HostURL("http://127.0.0.1:8080"); got != "http://localhost:8080" {
		t.Fatal(got)
	}
	if got := HostURL("https://dss.lab.test"); got != "https://dss.lab.test" {
		t.Fatal(got)
	}
}
