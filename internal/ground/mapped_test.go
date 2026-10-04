package ground

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/config"
)

// checkLoadPath loads testdata through New, the path every process takes
// (detect, dp, rid-ingest), and checks that the grid and the tile it
// reads say wantMapped through Mapped() and on the status line, and that
// they answer bit for bit what the in-memory parse answers (WP-19).
// mapped_unix_test.go wants a mapping, mapped_other_test.go the read
// into memory core falls back to elsewhere.
func checkLoadPath(t *testing.T, wantMapped bool) {
	t.Helper()
	s := loaded(t, FromConfig(config.Ground{}))
	if s.GeoidMapped() != wantMapped {
		t.Fatalf("GeoidMapped() = %v, want %v", s.GeoidMapped(), wantMapped)
	}
	st := attrs(s.StatusAttrs())
	if st["geoid_mapped"] != boolString(wantMapped) {
		t.Fatalf("status before a tile is read %v", st)
	}
	if _, ok := st["terrain_mapped"]; ok {
		t.Fatalf("terrain_mapped before a tile is read: %v", st)
	}

	env := s.Env(posKnown)
	if env.Ground != zones.GroundKnown || env.UndulationM == nil {
		t.Fatalf("env %+v", env)
	}
	if mapped, known := s.TerrainMapped(); !known || mapped != wantMapped {
		t.Fatalf("TerrainMapped() = %v, %v; want %v, true", mapped, known, wantMapped)
	}
	st = attrs(s.StatusAttrs())
	if st["terrain_mapped"] != boolString(wantMapped) || st["geoid_mapped"] != boolString(wantMapped) {
		t.Fatalf("status after a tile is read %v", st)
	}

	// The same answers as the files parsed in memory.
	data, err := os.ReadFile(filepath.Join("testdata", "geoid-constant.pgm"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := geoid.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	n, err := g.UndulationM(posKnown)
	if err != nil {
		t.Fatal(err)
	}
	if math.Float64bits(n) != math.Float64bits(*env.UndulationM) {
		t.Fatalf("undulation %v loaded, %v parsed", *env.UndulationM, n)
	}
	mem := New(Options{})
	mem.setTerrain(s.index, parsedTiles(terrain.DirOpener(filepath.Join("testdata", "tiles"), MaxTileBytes)))
	want := mem.Env(posKnown)
	if want.Ground != zones.GroundKnown || math.Float64bits(want.GroundM) != math.Float64bits(env.GroundM) {
		t.Fatalf("ground %v loaded, %+v parsed", env.GroundM, want)
	}
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// A tile read into memory says so on every platform: terrain_mapped is
// false once a parsed tile is in the cache.
func TestTileReadIntoMemorySaysNotMapped(t *testing.T) {
	s := New(Options{})
	s.setTerrain(terrain.Index{terrain.CellName(posKnown): "COP-DEM GLO-30"},
		parsedTiles(func(string) ([]byte, error) { return syntheticTile(), nil }))
	if _, known := s.TerrainMapped(); known {
		t.Fatal("TerrainMapped known before a tile is read")
	}
	if env := s.Env(posKnown); env.Ground != zones.GroundKnown {
		t.Fatalf("env %+v", env)
	}
	if mapped, known := s.TerrainMapped(); mapped || !known {
		t.Fatalf("TerrainMapped() = %v, %v; want false, true", mapped, known)
	}
	if st := attrs(s.StatusAttrs()); st["terrain_mapped"] != "false" {
		t.Fatalf("status %v", st)
	}
}

// A geoid file past MaxGeoidBytes is refused before it is mapped, as it
// was before it was read.
func TestGeoidPastTheBoundRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.pgm")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxGeoidBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	s := New(Options{GeoidFile: path, GeoidOnly: true})
	ps := s.Problems()
	if len(ps) != 1 || ps[0].State != StateUnavailable || ps[0].Reason != "GEOID_FILE: larger than 134217728 bytes" {
		t.Fatalf("problems %+v", ps)
	}
	if s.GeoidMapped() || s.Undulator() != nil {
		t.Fatal("a refused grid is loaded")
	}
	dir := New(Options{GeoidFile: t.TempDir(), GeoidOnly: true})
	if ps := dir.Problems(); len(ps) != 1 || ps[0].Reason != "GEOID_FILE: not a regular file" {
		t.Fatalf("problems %+v", ps)
	}
}
