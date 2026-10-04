package intents

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/zones"
)

var t0 = time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)

// refOf is a reference of id in state over [start, end].
func refOf(id string, state f3548.OperationalIntentState, start, end time.Time) f3548.OperationalIntentReference {
	return f3548.OperationalIntentReference{
		Id: id, Manager: "ussp-lab-01", UssBaseUrl: "https://ussp.example.test", State: state, Version: 1,
		TimeStart: f3548.Time{Format: f3548.RFC3339, Value: start}, TimeEnd: f3548.Time{Format: f3548.RFC3339, Value: end},
		UssAvailability: f3548.Normal,
	}
}

// fakeDSS answers the zone reads with every intent it holds and a
// position read with those whose box holds the position; err fails both.
type fakeDSS struct {
	mu     sync.Mutex
	refs   map[string]f3548.OperationalIntentReference
	boxes  map[string]geodesy.BBox
	err    error
	zoneQ  int
	pointQ int
	aois   []f3548.Volume4D
}

func newFakeDSS() *fakeDSS {
	return &fakeDSS{refs: map[string]f3548.OperationalIntentReference{}, boxes: map[string]geodesy.BBox{}}
}

func (f *fakeDSS) put(r f3548.OperationalIntentReference, box geodesy.BBox) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refs[r.Id], f.boxes[r.Id] = r, box
}

func (f *fakeDSS) remove(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.refs, id)
	delete(f.boxes, id)
}

func (f *fakeDSS) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeDSS) counts() (zone, point int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.zoneQ, f.pointQ
}

func (f *fakeDSS) Query(_ context.Context, aoi f3548.Volume4D) ([]f3548.OperationalIntentReference, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aois = append(f.aois, aoi)
	if f.err != nil {
		return nil, f.err
	}
	var out []f3548.OperationalIntentReference
	if c := aoi.Volume.OutlineCircle; c != nil {
		f.pointQ++
		p := c.Center.LatLon()
		for id := range f.refs {
			if f.boxes[id].Contains(p) {
				out = append(out, f.refs[id])
			}
		}
		return out, nil
	}
	f.zoneQ++
	for id := range f.refs {
		out = append(out, f.refs[id])
	}
	return out, nil
}

var errDown = errors.New("connection refused")

// uspaceZone is a U-space airspace around (lat, lon).
func uspaceZone(id string, lat, lon float64) *zones.Zone {
	d := 0.01
	ring := geodesy.Ring{{LatDeg: lat - d, LonDeg: lon - d}, {LatDeg: lat - d, LonDeg: lon + d}, {LatDeg: lat + d, LonDeg: lon + d},
		{LatDeg: lat + d, LonDeg: lon - d}, {LatDeg: lat - d, LonDeg: lon - d}}
	poly := &geodesy.Polygon{Rings: []geodesy.Ring{ring}}
	return &zones.Zone{Identifier: id, Country: "GEO", Type: core.ZoneUSpace, Polygon: poly, BBox: poly.BBox()}
}

func box(lat, lon, d float64) geodesy.BBox {
	return geodesy.BBox{MinLat: lat - d, MinLon: lon - d, MaxLat: lat + d, MaxLon: lon + d}
}

// clock is a settable clock.
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
