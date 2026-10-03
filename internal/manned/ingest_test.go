package manned

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/api/clients"
)

// E-03: Body's members are the ANSP's schema's, name for name (the
// pinned api/clients/ansp-schemas/track/manned/v1.json), and the
// openapi copy names the same members in MannedTrack.
func TestBodyMembersAreTheSchemas(t *testing.T) {
	raw, err := fs.ReadFile(clients.ANSPSchemas, schemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		Defs map[string]struct {
			Properties map[string]any `json:"properties"`
			Required   []string       `json:"required"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	want := slices.Sorted(maps.Keys(s.Defs["body"].Properties))
	var got []string
	rt := reflect.TypeFor[Body]()
	for i := range rt.NumField() {
		got = append(got, strings.Split(rt.Field(i).Tag.Get("json"), ",")[0])
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("Body %v\nschema %v", got, want)
	}
	// Every required member is never omitted on the way out.
	for _, r := range s.Defs["body"].Required {
		f, _ := rt.FieldByNameFunc(func(n string) bool {
			fl, _ := rt.FieldByName(n)
			return strings.Split(fl.Tag.Get("json"), ",")[0] == r
		})
		if strings.Contains(f.Tag.Get("json"), "omitempty") {
			t.Errorf("required %s is omitempty", r)
		}
	}
}

// The ANSP's own examples run through the validator: every valid one is
// accepted and published, every invalid one is refused (counted) or,
// for the wrong schema name, skipped as an unknown schema; nothing of an
// invalid example is published.
func TestTheANSPExamplesThroughTheIngest(t *testing.T) {
	for _, name := range []string{"live-ads-b.json", "source-disabled-pressure-only.json", "stale-after-silence.json"} {
		in, sink := newTestIngest(t)
		raw, _ := json.Marshal(example(t, name))
		in.HandleFrame(raw, t0.Add(time.Second))
		if len(sink.published()) != 1 || in.Counters.Get(CounterRefusedSchema) != 0 {
			t.Errorf("%s: published %d, refused %d", name, len(sink.published()), in.Counters.Get(CounterRefusedSchema))
		}
	}
	entries, err := fs.ReadDir(clients.ANSPSchemas, "ansp-schemas/examples/track/manned/v1/invalid")
	if err != nil || len(entries) == 0 {
		t.Fatalf("invalid examples: %v", err)
	}
	for _, e := range entries {
		in, sink := newTestIngest(t)
		raw, _ := fs.ReadFile(clients.ANSPSchemas, "ansp-schemas/examples/track/manned/v1/invalid/"+e.Name())
		in.HandleFrame(raw, t0.Add(time.Second))
		refused := in.Counters.Get(CounterRefusedSchema) + in.Counters.Get(CounterUnknownSchema)
		if len(sink.published()) != 0 || refused != 1 {
			t.Errorf("%s: published %d, refused or skipped %d", e.Name(), len(sink.published()), refused)
		}
	}
}

// D-03, E-01: a frame with both altitudes keeps them apart; one with
// pressure altitude only publishes alt_wgs84_m null, never the pressure
// value in its place; trust, source and source_instance are the ANSP's;
// the row carries the same and the subject is man.v1.<c3>.<c5>.<icao24>.
func TestMappingWithAndWithoutGeometricAltitude(t *testing.T) {
	in, sink := newTestIngest(t)
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(time.Second))
	in.HandleFrame(frame(t, t0.Add(time.Second), 0.3, map[string]any{"alt_wgs84_m": nil, "icao24": "4ca7c1"}), t0.Add(2*time.Second))
	pubs := sink.published()
	if len(pubs) != 2 {
		t.Fatalf("published %d", len(pubs))
	}
	both, only := decodeMsg(t, pubs[0])["body"].(map[string]any), decodeMsg(t, pubs[1])["body"].(map[string]any)
	if both["alt_pressure_m"] != 1524.0 || both["alt_wgs84_m"] != 1561.0 {
		t.Errorf("both altitudes: %v %v", both["alt_pressure_m"], both["alt_wgs84_m"])
	}
	if v, ok := only["alt_wgs84_m"]; !ok || v != nil || only["alt_pressure_m"] != 1524.0 {
		t.Errorf("pressure only: wgs84 %v (present %v), pressure %v", v, ok, only["alt_pressure_m"])
	}
	for _, b := range []map[string]any{both, only} {
		if b["trust"] != "surveillance" || b["source"] != "ansp_feed" || b["source_instance"] != "adsb-tbs" {
			t.Errorf("trust/source: %v %v %v", b["trust"], b["source"], b["source_instance"])
		}
	}
	if !strings.HasPrefix(pubs[0].Subject, "man.v1.") || !strings.HasSuffix(pubs[0].Subject, ".4ca7b5") || strings.Count(pubs[0].Subject, ".") != 4 {
		t.Errorf("subject %q", pubs[0].Subject)
	}
	r := pubs[1].Row
	if r.AltWGS84M != nil || r.AltPressureM == nil || *r.AltPressureM != 1524 || r.Trust != "surveillance" || r.Cell5 == nil ||
		!strings.HasPrefix(*r.Cell5, "c5:") || r.DedupeKey != DedupeKey("adsb-tbs", "4ca7c1", t0.Add(time.Second), StateLive) {
		t.Errorf("row %+v", r)
	}
	if len(sink.rows) != 2 {
		t.Errorf("rows %d", len(sink.rows))
	}
}

// Special values: null ground speed, track, vertical rate, callsign and
// emergency pass as null; a track of 360, an upper-case address, a
// pressure altitude spelled otherwise and a state of lost are refused
// by the ANSP's schema, counted, never published.
func TestSpecialValues(t *testing.T) {
	in, sink := newTestIngest(t)
	in.HandleFrame(frame(t, t0, 0.3, map[string]any{"gs_ms": nil, "track_deg": nil, "vrate_ms": nil, "callsign": nil, "emergency": nil}), t0.Add(time.Second))
	if len(sink.published()) != 1 {
		t.Fatalf("nulls refused: %v", in.Counters.Snapshot())
	}
	b := decodeMsg(t, sink.published()[0])["body"].(map[string]any)
	for _, k := range []string{"gs_ms", "track_deg", "vrate_ms", "callsign"} {
		if v, ok := b[k]; !ok || v != nil {
			t.Errorf("%s: %v %v", k, v, ok)
		}
	}
	for i, bad := range []map[string]any{{"track_deg": 360}, {"icao24": "4CA7B5"}, {"state": "lost"}, {"gs_ms": -1},
		{"squawk": "4529"}, {"trust": "broadcast"}, {"position": map[string]any{"lat": 91, "lng": 44}}} {
		in.HandleFrame(frame(t, t0.Add(time.Duration(i+2)*time.Second), 0.3, bad), t0.Add(10*time.Second))
	}
	if got := in.Counters.Get(CounterRefusedSchema); got != 7 || len(sink.published()) != 1 {
		t.Fatalf("refused %d, published %d", got, len(sink.published()))
	}
}

// T-12, E-01: a frame without rx_ts is placed at arrival with
// time_source system and counted; beside it a frame with rx_ts is placed
// by the ANSP's age (arrival minus age_s) with time_source provider. A
// frame without ts publishes a null ts and is counted.
func TestPlacementWithAndWithoutRxTS(t *testing.T) {
	in, sink := newTestIngest(t)
	arrival := t0.Add(time.Hour) // the ANSP's clock is an hour behind: it cancels
	in.HandleFrame(frame(t, t0, 0.5, nil), arrival)
	in.HandleFrame(frame(t, t0.Add(time.Second), 0.5, map[string]any{"icao24": "4ca7c1"}, "rx_ts", "ts"), arrival)
	pubs := sink.published()
	if len(pubs) != 2 {
		t.Fatalf("published %d", len(pubs))
	}
	placed, atArrival := pubs[0].Message, pubs[1].Message
	if placed.CapturedAt != stampOf(arrival.Add(-500*time.Millisecond)) || placed.TimeSource != "provider" || placed.RxTS != stampOf(arrival) {
		t.Errorf("placed by age: %s %s %s", placed.CapturedAt, placed.TimeSource, placed.RxTS)
	}
	if atArrival.CapturedAt != stampOf(arrival) || atArrival.TimeSource != "system" || atArrival.TS != nil {
		t.Errorf("at arrival: %s %s %v", atArrival.CapturedAt, atArrival.TimeSource, atArrival.TS)
	}
	if in.Counters.Get(CounterPlacedAtArrival) != 1 || in.Counters.Get(CounterWithoutTS) != 1 {
		t.Errorf("counters %v", in.Counters.Snapshot())
	}
	// The row still names the sample by its ANSP time.
	if !pubs[1].Row.SourceCapturedAt.Equal(t0.Add(time.Second)) {
		t.Errorf("source time %v", pubs[1].Row.SourceCapturedAt)
	}
}

// T-02, E-01: a sample whose age is beyond the 120 s spacing bound is
// placed at the bound and counted; one within it is not clamped. A
// snapshot is one batch: its samples keep their spacing.
func TestPlaceBatchClampingCounted(t *testing.T) {
	in, sink := newTestIngest(t)
	arrival := t0.Add(10 * time.Minute)
	in.HandleFrame(frame(t, t0, 10, nil), arrival)
	if in.Counters.Get(CounterClamped) != 0 || sink.published()[0].Message.CapturedAt != stampOf(arrival.Add(-10*time.Second)) {
		t.Fatalf("within the bound: %v %s", in.Counters.Snapshot(), sink.published()[0].Message.CapturedAt)
	}
	in.HandleFrame(frame(t, t0.Add(time.Second), 300, nil), arrival)
	if in.Counters.Get(CounterClamped) != 1 || sink.published()[1].Message.CapturedAt != stampOf(arrival.Add(-120*time.Second)) {
		t.Fatalf("past the bound: %v %s", in.Counters.Snapshot(), sink.published()[1].Message.CapturedAt)
	}
	// A snapshot of two aircraft written at the same instant, 1 s and 4 s
	// old: placed 3 s apart, the fresher 1 s before arrival.
	write := t0.Add(time.Hour)
	items := []json.RawMessage{
		json.RawMessage(frame(t, write.Add(-time.Second), 1, map[string]any{"icao24": "aaaaa1"})),
		json.RawMessage(frame(t, write.Add(-4*time.Second), 4, map[string]any{"icao24": "aaaaa2"})),
	}
	snap, _ := json.Marshal(map[string]any{"tracks": []any{}, "alerts": []any{}, "manned": items, "zones_version": nil})
	in.HandleFrame(envelopeFrame(SchemaSnapshot, write, json.RawMessage(snap)), arrival)
	pubs := sink.published()
	if len(pubs) != 4 || pubs[2].Message.CapturedAt != stampOf(arrival.Add(-time.Second)) || pubs[3].Message.CapturedAt != stampOf(arrival.Add(-4*time.Second)) {
		t.Fatalf("snapshot batch: %d %s %s", len(pubs), pubs[2].Message.CapturedAt, pubs[3].Message.CapturedAt)
	}
}

// E-01: dispatch on schema. A console/status/v1 frame keeps the feed
// fresh and is never published as a track; an adapter the ANSP calls
// stale ages its aircraft (republished stale, never removed); an unknown
// schema is counted and skipped, and the track beside it is still
// published.
func TestDispatchOnSchema(t *testing.T) {
	in, sink := newTestIngest(t)
	in.Feed.Connected(t0)
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(time.Second))
	in.HandleFrame(envelopeFrame("track/unknown/v9", t0, map[string]any{"x": 1}), t0.Add(time.Second))
	in.HandleFrame(frame(t, t0.Add(time.Second), 0.3, map[string]any{"icao24": "4ca7c1", "source_instance": "mlat-1"}), t0.Add(2*time.Second))
	if len(sink.published()) != 2 || in.Counters.Get(CounterUnknownSchema) != 1 {
		t.Fatalf("published %d, unknown %d", len(sink.published()), in.Counters.Get(CounterUnknownSchema))
	}
	src := []map[string]any{{"source": "ansp_feed", "source_instance": "adsb-tbs", "state": "stale", "since": stampOf(t0), "age_s": 9,
		"disabled_by": nil, "counters": map[string]any{"accepted": 1, "refused": 0}}}
	in.HandleFrame(statusFrame(t0.Add(3*time.Second), []map[string]any{{"id": "adsb-tbs", "state": "stale", "enabled": true}, {"id": "mlat-1", "state": "live", "enabled": true}}, src, "adapter_stale"),
		t0.Add(3*time.Second))
	pubs := sink.published()
	if len(pubs) != 3 {
		t.Fatalf("published %d", len(pubs))
	}
	aged := pubs[2]
	if aged.Message.Body.State != StateStale || aged.Message.Body.ICAO24 != "4ca7b5" || aged.Message.CapturedAt != pubs[0].Message.CapturedAt ||
		aged.Message.MsgID == pubs[0].Message.MsgID || aged.Row.State != StateStale {
		t.Fatalf("aged %+v", aged.Message)
	}
	if in.Len() != 2 || in.Counters.Get(CounterAgedStale) != 1 || in.Counters.Get(CounterStatusFrames) != 1 {
		t.Fatalf("held %d %v", in.Len(), in.Counters.Snapshot())
	}
	v := in.Feed.View(t0.Add(4 * time.Second))
	if v.State != FeedHealthy || !slices.Equal(v.Degraded, []string{"adapter_stale"}) || len(v.Sources) != 1 || *v.Dropped != 2 {
		t.Fatalf("feed %+v", v)
	}
	// A disabled adapter moves the aircraft on to source_disabled.
	in.HandleFrame(statusFrame(t0.Add(5*time.Second), []map[string]any{{"id": "adsb-tbs", "state": "disabled", "enabled": false}}, nil), t0.Add(5*time.Second))
	if p := sink.published(); len(p) != 4 || p[3].Message.Body.State != StateSourceDisabled {
		t.Fatalf("disabled adapter: %d", len(p))
	}
}

// E-02, B-05: the same sample again (the snapshot after a reconnection)
// is skipped, an older one is skipped, the same sample in a later state
// is republished, the same sample live again after it was aged is
// skipped, and a newer sample is published live.
func TestDedupePerAircraft(t *testing.T) {
	in, sink := newTestIngest(t)
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(time.Second))
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(2*time.Second))
	in.HandleFrame(frame(t, t0.Add(-time.Second), 0.3, nil), t0.Add(2*time.Second))
	if len(sink.published()) != 1 || in.Counters.Get(CounterDuplicates) != 1 || in.Counters.Get(CounterOlder) != 1 {
		t.Fatalf("published %d %v", len(sink.published()), in.Counters.Snapshot())
	}
	in.HandleFrame(frame(t, t0, 5, map[string]any{"state": "stale"}), t0.Add(6*time.Second))
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(7*time.Second))
	in.HandleFrame(frame(t, t0.Add(time.Second), 0.3, nil), t0.Add(8*time.Second))
	pubs := sink.published()
	if len(pubs) != 3 || pubs[1].Message.Body.State != StateStale || pubs[2].Message.Body.State != StateLive {
		t.Fatalf("published %d", len(pubs))
	}
}

// E-10: the per-aircraft state map holds MaxAircraft; past it the
// aircraft updated longest ago is forgotten and counted.
func TestPerAircraftStateBounded(t *testing.T) {
	in, sink := newTestIngest(t)
	in.S.MaxAircraft = 3
	for i := range 5 {
		in.HandleFrame(frame(t, t0.Add(time.Duration(i)*time.Second), 0.3, map[string]any{"icao24": fmt.Sprintf("00000%d", i)}), t0.Add(10*time.Second))
	}
	if in.Len() != 3 || in.Counters.Get(CounterEvicted) != 2 || len(sink.published()) != 5 {
		t.Fatalf("held %d evicted %d", in.Len(), in.Counters.Get(CounterEvicted))
	}
	// The forgotten 000000 is new again; the held 000004 is a duplicate.
	in.HandleFrame(frame(t, t0, 0.3, map[string]any{"icao24": "000000"}), t0.Add(11*time.Second))
	in.HandleFrame(frame(t, t0.Add(4*time.Second), 0.3, map[string]any{"icao24": "000004"}), t0.Add(11*time.Second))
	if len(sink.published()) != 6 || in.Counters.Get(CounterDuplicates) != 1 {
		t.Fatalf("published %d %v", len(sink.published()), in.Counters.Snapshot())
	}
}

// B-11, E-01: a switched-off adapter's frames are refused and counted
// and its aircraft are aged source_disabled, never removed; another
// adapter's still pass; the feed switched off ages every aircraft.
func TestSourceSwitches(t *testing.T) {
	in, sink := newTestIngest(t)
	g := &gate{}
	in.Gate = g
	in.HandleFrame(frame(t, t0, 0.3, nil), t0.Add(time.Second))
	in.HandleFrame(frame(t, t0, 0.3, map[string]any{"icao24": "4ca7c1", "source_instance": "mlat-1"}), t0.Add(time.Second))
	g.set("adsb-tbs", true)
	if n := in.ApplySwitches(t0.Add(2 * time.Second)); n != 1 {
		t.Fatalf("aged %d", n)
	}
	in.HandleFrame(frame(t, t0.Add(time.Second), 0.3, nil), t0.Add(3*time.Second))
	in.HandleFrame(frame(t, t0.Add(time.Second), 0.3, map[string]any{"icao24": "4ca7c1", "source_instance": "mlat-1"}), t0.Add(3*time.Second))
	pubs := sink.published()
	if len(pubs) != 4 || pubs[2].Message.Body.State != StateSourceDisabled || pubs[3].Message.Body.ICAO24 != "4ca7c1" ||
		in.Counters.Get(CounterRefusedDisabled) != 1 || in.Len() != 2 {
		t.Fatalf("published %d %v", len(pubs), in.Counters.Snapshot())
	}
	g.set("ansp", true)
	if n := in.ApplySwitches(t0.Add(4 * time.Second)); n != 1 {
		t.Fatalf("feed off aged %d", n)
	}
	if in.ApplySwitches(t0.Add(5*time.Second)) != 0 {
		t.Fatal("aged twice")
	}
}
