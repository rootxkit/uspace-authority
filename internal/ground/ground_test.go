package ground

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/config"
)

// The positions of testdata/tiles (see testIndex).
var (
	posKnown      = core.LatLon{LatDeg: 41.5, LonDeg: 44.75}    // sample (2, 3): 423 m
	posNoData     = core.LatLon{LatDeg: 41.875, LonDeg: 44.125} // around sample (1, 1)
	posSea        = core.LatLon{LatDeg: 40.5, LonDeg: 44.5}
	posUnreadable = core.LatLon{LatDeg: 41.5, LonDeg: 45.5}
	posMissing    = core.LatLon{LatDeg: 42.5, LonDeg: 44.5}
	posNotIndexed = core.LatLon{LatDeg: 43.5, LonDeg: 44.5}
	tbilisi       = core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}
)

// clock is a settable clock for the tile retry.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func loaded(t *testing.T, o Options) *Service {
	t.Helper()
	if o.Dir == "" {
		o.Dir = filepath.Join("testdata", "tiles")
	}
	if o.GeoidFile == "" {
		o.GeoidFile = filepath.Join("testdata", "geoid-constant.pgm")
	}
	s := New(o)
	if p := s.Problems(); len(p) != 0 {
		t.Fatalf("problems with both inputs loaded: %+v", p)
	}
	return s
}

// logLines runs s.Log into a JSON handler and returns the lines.
func logLines(t *testing.T, s *Service) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	s.Log(slog.New(slog.NewJSONHandler(&buf, nil)))
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		out = append(out, m)
	}
	return out
}

// parsedTiles turns a byte opener into the tile opener setTerrain takes,
// parsing with core's terrain.ParseTile (a tile in memory, not mapped).
func parsedTiles(open func(string) ([]byte, error)) func(string) (*terrain.Tile, error) {
	return func(cell string) (*terrain.Tile, error) {
		data, err := open(cell)
		if err != nil {
			return nil, err
		}
		return terrain.ParseTile(data)
	}
}

func attrs(as []slog.Attr) map[string]string {
	m := map[string]string{}
	for _, a := range as {
		m[a.Key] = a.Value.String()
	}
	return m
}

// E-02: started with nothing configured, the service says so for both
// inputs, every lookup is "not configured" and without an undulation,
// and the core interfaces are nil interfaces (the callers' "none"
// branches run).
func TestNothingConfiguredSaysSo(t *testing.T) {
	s := New(FromConfig(config.Ground{}))
	st := attrs(s.StatusAttrs())
	if st["terrain"] != StateNotConfigured || st["geoid"] != StateNotConfigured {
		t.Fatalf("status %v", st)
	}
	if _, ok := st["terrain_attribution"]; ok {
		t.Error("attribution shown without a DEM")
	}
	env := s.Env(tbilisi)
	if env.Ground != zones.GroundNotConfigured || env.UndulationM != nil {
		t.Fatalf("env %+v", env)
	}
	if s.Undulator() != nil || s.Ground() != nil || s.TerrainCounters() != nil || s.Elevation(tbilisi) != nil {
		t.Fatal("an interface or counter without its input")
	}
	if c := s.Counters(); c.Get(CounterGroundNotConfigured) != 1 || c.Get(CounterUndulationNone) != 1 {
		t.Fatalf("counters %v", c.Snapshot())
	}
	ps := s.Problems()
	if len(ps) != 2 || ps[0].Input != InputTerrain || ps[1].Input != InputGeoid ||
		ps[0].State != StateNotConfigured || !strings.Contains(ps[0].Effect, "limit_not_judged") {
		t.Fatalf("problems %+v", ps)
	}
	lines := logLines(t, s)
	if len(lines) != 3 || lines[0]["msg"] != "ground datasets" || lines[0]["terrain"] != StateNotConfigured ||
		lines[1]["level"] != "WARN" || lines[1]["input"] != InputTerrain || lines[2]["input"] != InputGeoid {
		t.Fatalf("log %v", lines)
	}
}

// E-02 presence: both inputs loaded, the start line names the dataset,
// the attribution, the cells and the geoid, and nothing is a problem.
func TestBothLoadedSaySo(t *testing.T) {
	s := loaded(t, FromConfig(config.Ground{GroundTileCache: 4, GroundRetryAfterS: 30}))
	lines := logLines(t, s)
	if len(lines) != 1 {
		t.Fatalf("log %v", lines)
	}
	l := lines[0]
	if l["terrain"] != StateLoaded || l["geoid"] != StateLoaded || l["terrain_attribution"] != terrain.Attribution ||
		l["terrain_cells"] != float64(4) || l["terrain_retry_after_s"] != float64(30) ||
		fmt.Sprint(l["terrain_datasets"]) != "[COP-DEM GLO-30]" || !strings.Contains(fmt.Sprint(l["geoid_description"]), "15.9") {
		t.Fatalf("start line %v", l)
	}
	if s.Undulator() == nil || s.Ground() == nil {
		t.Fatal("interfaces nil with both inputs loaded")
	}
}

// Known, unknown, sea and unreadable, through Env (D-04): never 0 m for
// what is not known; sea is 0 m and reads no tile.
func TestEnvGroundKinds(t *testing.T) {
	s := loaded(t, Options{})
	for _, c := range []struct {
		name  string
		p     core.LatLon
		kind  zones.GroundKind
		wantM float64
	}{
		{"known", posKnown, zones.GroundKnown, 423},
		{"sea", posSea, zones.GroundKnown, 0},
		{"nodata", posNoData, zones.GroundUnknown, 0},
		{"unreadable", posUnreadable, zones.GroundUnknown, 0},
		{"missing", posMissing, zones.GroundUnknown, 0},
		{"not indexed", posNotIndexed, zones.GroundUnknown, 0},
		{"invalid position", core.LatLon{LatDeg: 91, LonDeg: 0}, zones.GroundUnknown, 0},
	} {
		env := s.Env(c.p)
		if env.Ground != c.kind || env.GroundM != c.wantM {
			t.Errorf("%s: %+v, want kind %v at %v m", c.name, env, c.kind, c.wantM)
		}
	}
	tc := s.TerrainCounters()
	if tc.Get(terrain.CounterNoData) != 1 || tc.Get(terrain.CounterUnknownCell) != 1 ||
		tc.Get(terrain.CounterTileReadFailed) != 2 || tc.Get(terrain.CounterTileUnavailable) != 2 ||
		tc.Get(terrain.CounterInvalidPosition) != 1 || tc.Get(terrain.CounterTilesLoaded) != 1 {
		t.Fatalf("terrain counters %v", tc.Snapshot())
	}
	if c := s.Counters(); c.Get(CounterGroundKnown) != 2 || c.Get(CounterGroundUnknown) != 5 {
		t.Fatalf("counters %v", c.Snapshot())
	}
	e := s.Elevation(posKnown)
	if e == nil || e.ElevationM != 423 || e.Dataset != "COP-DEM GLO-30" || e.SpacingM <= 0 {
		t.Fatalf("elevation %+v", e)
	}
	if s.Elevation(posMissing) != nil || s.Elevation(core.LatLon{LatDeg: math.NaN()}) != nil {
		t.Fatal("an elevation for unknown ground")
	}
}

// E-02, D-04: a tile listed but missing is unknown, counted, and not read
// again before the retry interval; after it, it is read again, counted.
func TestMissingTileRetriedAfterTheInterval(t *testing.T) {
	ck := &clock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	s := loaded(t, Options{RetryAfter: 30 * time.Second, Now: ck.now})
	tc := s.TerrainCounters()
	for range 5 {
		if s.Env(posMissing).Ground != zones.GroundUnknown {
			t.Fatal("missing tile not unknown")
		}
	}
	if tc.Get(terrain.CounterTileReadFailed) != 1 || tc.Get(terrain.CounterTileUnavailable) != 5 {
		t.Fatalf("within the interval: %v", tc.Snapshot())
	}
	if st := attrs(s.StatusAttrs()); st["terrain_retry_after_s"] != "30" {
		t.Fatalf("status %v", st)
	}
	ck.add(31 * time.Second)
	s.Env(posMissing)
	if tc.Get(terrain.CounterTileReadRetried) != 1 || tc.Get(terrain.CounterTileReadFailed) != 2 {
		t.Fatalf("after the interval: %v", tc.Snapshot())
	}
}

// E-10: the tile cache holds at most GROUND_TILE_CACHE tiles; past it the
// least recently used is evicted, counted.
func TestTileCacheBound(t *testing.T) {
	idx := terrain.Index{}
	var reads int
	var mu sync.Mutex
	for lat := 40; lat < 43; lat++ {
		idx[terrain.CellName(core.LatLon{LatDeg: float64(lat) + 0.5, LonDeg: 44.5})] = "COP-DEM GLO-30"
	}
	s := New(Options{MaxTiles: 2})
	s.setTerrain(idx, parsedTiles(func(cell string) ([]byte, error) {
		mu.Lock()
		reads++
		mu.Unlock()
		var lat int
		if _, err := fmt.Sscanf(cell, "N%02dE044", &lat); err != nil {
			return nil, err
		}
		return tileBytes(5, 5, float64(lat+1), 44, 0.25, "COP-DEM GLO-30",
			func(int, int) float64 { return 100 }, nil), nil
	}))
	for lat := 40; lat < 43; lat++ {
		if env := s.Env(core.LatLon{LatDeg: float64(lat) + 0.5, LonDeg: 44.5}); env.Ground != zones.GroundKnown || env.GroundM != 100 {
			t.Fatalf("cell %d: %+v", lat, env)
		}
	}
	tc := s.TerrainCounters()
	if tc.Get(terrain.CounterTilesEvicted) != 1 || len(s.store.Cached()) != 2 || reads != 3 {
		t.Fatalf("evicted %d, cached %v, reads %d", tc.Get(terrain.CounterTilesEvicted), s.store.Cached(), reads)
	}
	if st := attrs(s.StatusAttrs()); st["terrain_tiles_cached"] != "2" {
		t.Fatalf("status %v", st)
	}
}

// Configured but unreadable: said as unavailable with the reason, and
// every lookup is unknown ground and no undulation, never a guess.
func TestConfiguredButUnreadable(t *testing.T) {
	for _, c := range []struct {
		name, dir, geoid, terrainWhy, geoidWhy string
	}{
		{"absent", filepath.Join("testdata", "no-such-dir"), filepath.Join("testdata", "no-such.pgm"), "GROUND_DIR", "GEOID_FILE"},
		{"invalid", filepath.Join("testdata", "tiles-bad"), filepath.Join("testdata", "geoid-not-a-grid.pgm"), "index.json", "GEOID_FILE"},
		{"no index", "testdata", filepath.Join("testdata", "tiles", "index.json"), "index.json", "GEOID_FILE"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := New(Options{Dir: c.dir, GeoidFile: c.geoid})
			ps := s.Problems()
			if len(ps) != 2 || ps[0].State != StateUnavailable || !strings.Contains(ps[0].Reason, c.terrainWhy) ||
				ps[1].State != StateUnavailable || !strings.Contains(ps[1].Reason, c.geoidWhy) {
				t.Fatalf("problems %+v", ps)
			}
			env := s.Env(posKnown)
			if env.Ground != zones.GroundUnknown || env.UndulationM != nil {
				t.Fatalf("env %+v", env)
			}
			if s.Counters().Get(CounterTerrainUnavailable) != 1 || s.Undulator() != nil || s.Ground() != nil {
				t.Fatalf("counters %v", s.Counters().Snapshot())
			}
			lines := logLines(t, s)
			if len(lines) != 3 || lines[1]["reason"] == nil || lines[2]["state"] != StateUnavailable {
				t.Fatalf("log %v", lines)
			}
		})
	}
}

// The undulation comes from the grid; a position the grid refuses is no
// undulation, counted.
func TestEnvUndulation(t *testing.T) {
	s := loaded(t, Options{})
	env := s.Env(tbilisi)
	if env.UndulationM == nil || math.Abs(*env.UndulationM-constantGeoidM) > 1e-9 {
		t.Fatalf("undulation %v", env.UndulationM)
	}
	if env = s.Env(core.LatLon{LatDeg: 95, LonDeg: 0}); env.UndulationM != nil {
		t.Fatalf("undulation at 95N: %v", *env.UndulationM)
	}
	if s.Counters().Get(CounterGeoidFailed) != 1 {
		t.Fatalf("counters %v", s.Counters().Snapshot())
	}
}

// rid-ingest uses the geoid alone: terrain is neither loaded nor listed
// as a problem, and the status says only the geoid.
func TestGeoidOnly(t *testing.T) {
	s := New(FromGeoidConfig(config.Geoid{GeoidFile: filepath.Join("testdata", "geoid-constant.pgm")}))
	if len(s.Problems()) != 0 || s.Ground() != nil || s.Undulator() == nil {
		t.Fatalf("problems %+v", s.Problems())
	}
	st := attrs(s.StatusAttrs())
	if _, ok := st["terrain"]; ok || st["geoid"] != StateLoaded {
		t.Fatalf("status %v", st)
	}
	none := New(FromGeoidConfig(config.Geoid{}))
	if ps := none.Problems(); len(ps) != 1 || ps[0].Input != InputGeoid || none.Undulator() != nil {
		t.Fatalf("problems %+v", ps)
	}
}
