package ground

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/vectors"
	"github.com/rootxkit/uspace-core/zones"
)

// Tolerances of terrain_geoid.json's header, mirrored so that a change in
// the lab shows here.
const (
	tolSyntheticM = 1e-9
	tolGeoLibM    = 1e-9
)

type vectorInput struct {
	Function string  `json:"function"`
	LatDeg   float64 `json:"lat_deg"`
	LonDeg   float64 `json:"lon_deg"`
	Grid     string  `json:"grid,omitempty"`
	Tile     string  `json:"tile,omitempty"`
}

// realGrids loads GeographicLib's grids from USPACE_GEOID_DIR once each,
// through New, as a process does from GEOID_FILE.
var realGrids = struct {
	sync.Mutex
	s map[string]*Service
}{s: map[string]*Service{}}

func realGrid(name string) (*Service, error) {
	realGrids.Lock()
	defer realGrids.Unlock()
	if s, ok := realGrids.s[name]; ok {
		return s, nil
	}
	dir := os.Getenv("USPACE_GEOID_DIR")
	if dir == "" {
		return nil, fmt.Errorf("USPACE_GEOID_DIR unset (deploy/fetch-ground.sh --geoid-only DIR)")
	}
	s := New(Options{GeoidFile: filepath.Join(dir, name+".pgm"), GeoidOnly: true})
	if s.Undulator() == nil {
		return nil, fmt.Errorf("%s: %+v", name, s.Problems())
	}
	realGrids.s[name] = s
	return s, nil
}

// terrain_geoid.json through Env (RunOwned "authority"): the cell a
// position names, a tile elevation (null is GroundUnknown, never 0 m),
// and the geoid undulation. The GeographicLib reference cases are skipped,
// visibly, without the real grids.
func TestVectorsTerrainGeoid(t *testing.T) {
	f := vectors.Load(t, "terrain_geoid.json")
	for key, want := range map[string]float64{"synthetic": tolSyntheticM, "geographiclib references": tolGeoLibM} {
		if got, ok := f.FloatTolerance(key); !ok || got != want {
			t.Fatalf("tolerance %q: header %v (%v), test applies %v", key, got, ok, want)
		}
	}
	synthetic := New(Options{GeoidFile: filepath.Join("testdata", "geoid-synthetic.pgm")})
	if synthetic.Undulator() == nil {
		t.Fatalf("synthetic geoid: %+v", synthetic.Problems())
	}
	var mu sync.Mutex
	ran := map[string]int{}
	skipped := 0
	t.Cleanup(func() { t.Logf("terrain_geoid.json: ran %v, skipped %d (GeographicLib grids absent)", ran, skipped) })
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		var in vectorInput
		c.Decode(t, &in, nil)
		p := core.LatLon{LatDeg: in.LatDeg, LonDeg: in.LonDeg}
		switch in.Function {
		case "cell_name":
			var exp struct {
				Cell string `json:"cell"`
			}
			c.Decode(t, nil, &exp)
			// Only the expected cell is in the index: the ground is
			// known at p exactly when p names that cell.
			s := New(Options{})
			s.setTerrain(terrain.Index{exp.Cell: terrain.SeaDataset}, nil)
			if env := s.Env(p); env.Ground != zones.GroundKnown || s.TerrainCounters().Get(terrain.CounterUnknownCell) != 0 {
				t.Errorf("%+v does not name %s: %+v", p, exp.Cell, env)
			}
		case "terrain_tile_elevation":
			if in.Tile != "synthetic" {
				t.Fatalf("unknown tile %q", in.Tile)
			}
			var exp struct {
				ElevationM *float64 `json:"elevation_m"`
			}
			c.Decode(t, nil, &exp)
			// The cell of p is indexed and its tile is the synthetic
			// one, as the vectors read it (clamped at its edges).
			s := New(Options{})
			s.setTerrain(terrain.Index{terrain.CellName(p): "COP-DEM GLO-30"},
				func(string) ([]byte, error) { return syntheticTile(), nil })
			env := s.Env(p)
			if exp.ElevationM == nil {
				if env.Ground != zones.GroundUnknown {
					t.Errorf("env %+v, want unknown ground", env)
				}
				break
			}
			if env.Ground != zones.GroundKnown {
				t.Fatalf("env %+v, want known ground", env)
			}
			vectors.Near(t, "elevation_m", env.GroundM, *exp.ElevationM, tolSyntheticM)
		case "geoid_undulation":
			var exp struct {
				UndulationM float64 `json:"undulation_m"`
			}
			c.Decode(t, nil, &exp)
			s, tol := synthetic, tolSyntheticM
			if in.Grid != "synthetic" {
				rs, err := realGrid(in.Grid)
				if err != nil {
					mu.Lock()
					skipped++
					mu.Unlock()
					t.Skipf("needs %s.pgm in USPACE_GEOID_DIR: %v", in.Grid, err)
				}
				s, tol = rs, tolGeoLibM
			}
			env := s.Env(p)
			if env.UndulationM == nil {
				t.Fatalf("no undulation at %+v", p)
			}
			vectors.Near(t, "undulation_m", *env.UndulationM, exp.UndulationM, tol)
		default:
			t.Fatalf("unknown function %q", in.Function)
		}
		mu.Lock()
		ran[in.Function]++
		mu.Unlock()
	})
}
