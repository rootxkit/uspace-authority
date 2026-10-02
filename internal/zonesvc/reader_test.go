package zonesvc

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// fakeSource serves rows or an error.
type fakeSource struct {
	mu   sync.Mutex
	rows []ProjectedRow
	err  error
	n    int
}

func (f *fakeSource) LoadZones(context.Context) ([]ProjectedRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return f.rows, f.err
}

func (f *fakeSource) set(rows []ProjectedRow, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows, f.err = rows, err
}

func projected(id string, version int, f string, from, to time.Time) ProjectedRow {
	return ProjectedRow{Dataset: DatasetZones, Identifier: id, ZoneVersion: version, Feature: json.RawMessage(f),
		ValidFrom: from, ValidTo: to, ZonesVersion: int64(version)}
}

var inside = core.LatLon{LatDeg: 41.7, LonDeg: 44.8}

func candidateTypes(r *ProjectionReader) []string {
	var out []string
	for _, z := range r.Index().Candidates(inside) {
		out = append(out, z.Identifier+":"+string(z.Type))
	}
	return out
}

func TestReaderIndexesTheNewestVersionInForce(t *testing.T) {
	change := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	src := &fakeSource{rows: []ProjectedRow{
		projected("TST001", 1, feature(zoneOpts{}), t0, change),
		projected("TST001", 2, feature(zoneOpts{typ: "CONDITIONAL"}), change.Add(time.Second), t1),
		projected("FAR001", 1, feature(zoneOpts{identifier: "FAR001", geometry: polygon(42.5, 45.5, 0.01, "AMSL")}), t0, t1),
	}}
	now := testNow
	r := &ProjectionReader{Source: src, Counters: &core.Counters{}, Now: func() time.Time { return now }}
	if r.Index() != nil || r.StatusAttrs()[0].Value.Bool() {
		t.Fatal("an index before the first read")
	}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := candidateTypes(r); len(got) != 1 || got[0] != "TST001:PROHIBITED" {
		t.Fatalf("%v", got)
	}
	if r.Version() != 2 || !r.next().Equal(change.Add(time.Nanosecond)) {
		t.Fatalf("version %d next %s", r.Version(), r.next())
	}
	// At the boundary the rows held are rebuilt without a read.
	now = change.Add(2 * time.Second)
	r.rebuild()
	if got := candidateTypes(r); len(got) != 1 || got[0] != "TST001:CONDITIONAL" {
		t.Fatalf("%v", got)
	}
	// Past every period nothing is judged.
	now = t1.Add(time.Second)
	r.rebuild()
	if got := candidateTypes(r); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// G-08: a failed read keeps the index held; it is counted.
func TestReaderKeepsTheIndexWhenAReadFails(t *testing.T) {
	src := &fakeSource{rows: []ProjectedRow{projected("TST001", 1, feature(zoneOpts{}), t0, t1)}}
	r := &ProjectionReader{Source: src, Counters: &core.Counters{}, Now: func() time.Time { return testNow }}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	src.set(nil, errInjected)
	if err := r.Refresh(context.Background()); err == nil {
		t.Fatal("a failed read reported success")
	}
	if got := candidateTypes(r); len(got) != 1 || r.Counters.Get(CounterReaderReadFailed) != 1 {
		t.Fatalf("%v %v", got, r.Counters.Snapshot())
	}
	// A good read with no rows empties the index (an empty sky is then
	// what the projection says).
	src.set([]ProjectedRow{}, nil)
	if err := r.Refresh(context.Background()); err != nil || len(candidateTypes(r)) != 0 {
		t.Fatalf("%v", err)
	}
}

func TestReaderNamesZonesItCannotJudgeAndThoseNeedingGround(t *testing.T) {
	daylight := `[{"startDateTime":"2026-10-01T00:00:00Z","endDateTime":"2026-10-08T00:00:00Z","schedule":[{"day":["ANY"],"startEvent":"SR","endEvent":"SS"}]}]`
	src := &fakeSource{rows: []ProjectedRow{
		projected("DAY001", 1, feature(zoneOpts{identifier: "DAY001", limited: daylight}), t0, t1),
		projected("AGL001", 1, feature(zoneOpts{identifier: "AGL001", upperRef: "AGL"}), t0, t1),
		projected("ELL001", 1, feature(zoneOpts{identifier: "ELL001", upperRef: "WGS84"}), t0, t1),
	}}
	r := &ProjectionReader{Source: src, Counters: &core.Counters{}, Now: func() time.Time { return testNow }}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	nj := r.NotJudged()
	if len(nj) != 1 || !strings.HasPrefix(nj[0], "zones/DAY001@1") || !strings.Contains(nj[0], "daylight") {
		t.Fatalf("%v", nj)
	}
	terrain, geoid := r.Ground()
	if len(terrain) != 1 || terrain[0] != "GEO/AGL001" || len(geoid) != 1 || geoid[0] != "GEO/ELL001" {
		t.Fatalf("terrain %v geoid %v", terrain, geoid)
	}
	if got := candidateTypes(r); len(got) != 2 {
		t.Fatalf("the judgeable zones are indexed: %v", got)
	}
	attrs := map[string]any{}
	for _, a := range r.StatusAttrs() {
		attrs[a.Key] = a.Value.Any()
	}
	if attrs["zones_projection_loaded"] != true || attrs["zones"] != int64(2) || attrs["projection_age_s"] == nil {
		t.Fatalf("%v", attrs)
	}
	// With nothing to report the lists are empty.
	src.set([]ProjectedRow{projected("AMS001", 1, feature(zoneOpts{identifier: "AMS001"}), t0, t1)}, nil)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	terrain, geoid = r.Ground()
	if len(r.NotJudged()) != 0 || len(terrain) != 0 || len(geoid) != 0 {
		t.Fatalf("%v %v %v", r.NotJudged(), terrain, geoid)
	}
}

func TestReaderRunsOnNotifyAndAtABoundary(t *testing.T) {
	start := time.Now()
	src := &fakeSource{rows: []ProjectedRow{projected("TST001", 1, feature(zoneOpts{}), start.Add(300*time.Millisecond), start.Add(time.Hour))}}
	r := &ProjectionReader{Source: src, Counters: &core.Counters{}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx, time.Hour); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, func() bool { return r.Index() != nil })
	if len(candidateTypes(r)) != 0 {
		t.Fatal("judged before its period started")
	}
	waitFor(t, func() bool { return len(candidateTypes(r)) == 1 })
	src.set([]ProjectedRow{}, nil)
	r.Notify()
	waitFor(t, func() bool { return len(candidateTypes(r)) == 0 })
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met in 5 s")
}

// The service's projection, read as a reader loads it, is the index.
func TestPublishedZoneReachesTheReaderIndex(t *testing.T) {
	s, _, pr, _ := newService(t)
	publishOne(t, s, feature(zoneOpts{}))
	src := &fakeSource{rows: pr.rowsAsLoaded()}
	r := &ProjectionReader{Source: src, Now: func() time.Time { return testNow }}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := candidateTypes(r); len(got) != 1 || got[0] != "TST001:PROHIBITED" {
		t.Fatalf("%v", got)
	}
}
