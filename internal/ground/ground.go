package ground

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/terrain"
	"github.com/rootxkit/uspace-core/zones"

	"github.com/rootxkit/uspace-authority/internal/config"
)

// The state of each input, on the status line and in Problems.
const (
	StateLoaded        = "loaded"
	StateNotConfigured = "not configured"
	StateUnavailable   = "unavailable"
)

// The inputs Problems names.
const (
	InputTerrain = "terrain"
	InputGeoid   = "geoid"
)

// IndexFile is the name of the tile index inside GROUND_DIR.
const IndexFile = "index.json"

// Bounds of the files read (E-10). The EGM2008 2.5' grid is 8640 x 4321
// 16-bit samples, about 75 MB; a GLO-30 tile about 26 MB. Both are mapped
// read-only where the platform can (geoid.LoadMapped,
// terrain.MappedDirOpener; WP-19), so the processes on one host share one
// copy in the page cache: a file must be replaced by renaming a new one
// over it, never rewritten in place.
const (
	MaxGeoidBytes = 128 << 20
	MaxTileBytes  = 64 << 20
)

// Counter names of Counters (E-09). The tile cache's own counters
// (tiles_loaded, tiles_evicted, tile_read_failed, tile_read_retried,
// tile_unavailable, unknown_cell, nodata, invalid_position) are
// TerrainCounters.
const (
	CounterGroundKnown         = "ground_known"
	CounterGroundUnknown       = "ground_unknown"
	CounterGroundNotConfigured = "ground_not_configured"
	CounterTerrainUnavailable  = "ground_terrain_unavailable" // a lookup answered unknown because the index could not be read
	CounterUndulationNone      = "undulation_unavailable"     // a lookup without a geoid undulation
	CounterGeoidFailed         = "geoid_lookup_failed"        // the grid refused the position
)

// Options configure a Service. Every field is optional.
type Options struct {
	// Dir holds the tiles <cell>.pgm and index.json (GROUND_DIR); empty
	// is no terrain.
	Dir string
	// GeoidFile is the GeographicLib grid (GEOID_FILE); empty is no
	// geoid.
	GeoidFile string
	// MaxTiles bounds the tile cache (terrain.DefaultMaxTiles when 0).
	MaxTiles int
	// RetryAfter is how long a tile that could not be read stays unknown
	// before it is read again (terrain.DefaultRetryAfter when 0).
	RetryAfter time.Duration
	// GeoidOnly says the process uses the geoid alone (rid-ingest): the
	// status says nothing about terrain and Problems does not list it.
	GeoidOnly bool
	// Now is the clock of the retry (time.Now when nil).
	Now func() time.Time
}

// FromConfig maps a process's ground configuration onto Options.
func FromConfig(c config.Ground) Options {
	return Options{
		Dir: c.GroundDir, GeoidFile: c.GeoidFile, MaxTiles: c.GroundTileCache,
		RetryAfter: time.Duration(c.GroundRetryAfterS) * time.Second,
	}
}

// FromGeoidConfig maps the geoid-only configuration onto Options.
func FromGeoidConfig(c config.Geoid) Options {
	return Options{GeoidFile: c.GeoidFile, GeoidOnly: true}
}

// Problem is one input that cannot be used, and what is therefore not
// judged (Z-09); WP-12 logs it at error level when a PROHIBITED zone
// needs it.
type Problem struct {
	Input  string // InputTerrain or InputGeoid
	State  string // StateNotConfigured or StateUnavailable
	Reason string // why, for unavailable; empty for not configured
	Effect string // what is not judged because of it
}

// Service is the process's terrain and geoid. It is safe for concurrent
// use: the tile cache is core's, and everything else is fixed at New.
type Service struct {
	o          Options
	store      *terrain.Store
	index      terrain.Index
	grid       *geoid.Grid
	terrain    string
	terrainWhy string
	geoid      string
	geoidWhy   string
	retryAfter time.Duration
	counters   *core.Counters
	// tileMapped is the Mapped() of the last tile read: tileUnread before
	// the first, then tileInMemory or tileMappedFile.
	tileMapped atomic.Int32
}

// The values of Service.tileMapped.
const (
	tileUnread int32 = iota
	tileInMemory
	tileMappedFile
)

// New loads what o names. It never fails: an input that is not
// configured or cannot be read is reported by StatusAttrs, Log and
// Problems, and every lookup answers as without it (unknown ground, no
// undulation), never a guess.
func New(o Options) *Service {
	s := &Service{o: o, counters: &core.Counters{}, terrain: StateNotConfigured, geoid: StateNotConfigured}
	s.retryAfter = o.RetryAfter
	if s.retryAfter <= 0 {
		s.retryAfter = terrain.DefaultRetryAfter
	}
	if o.Dir != "" && !o.GeoidOnly {
		idx, err := readIndex(o.Dir)
		if err != nil {
			s.terrain, s.terrainWhy = StateUnavailable, err.Error()
		} else {
			s.setTerrain(idx, terrain.MappedDirOpener(o.Dir, MaxTileBytes))
		}
	}
	if o.GeoidFile != "" {
		g, err := readGeoid(o.GeoidFile)
		if err != nil {
			s.geoid, s.geoidWhy = StateUnavailable, err.Error()
		} else {
			s.grid, s.geoid = g, StateLoaded
		}
	}
	return s
}

// setTerrain builds the store over idx, reading tiles through openTile
// (terrain.MappedDirOpener in New) and noting whether each is mapped.
func (s *Service) setTerrain(idx terrain.Index, openTile func(string) (*terrain.Tile, error)) {
	s.index = idx
	opts := terrain.StoreOptions{MaxTiles: s.o.MaxTiles, RetryAfter: s.retryAfter, Now: s.o.Now}
	if openTile != nil {
		opts.OpenTile = func(cell string) (*terrain.Tile, error) {
			t, err := openTile(cell)
			if err == nil && t != nil {
				if t.Mapped() {
					s.tileMapped.Store(tileMappedFile)
				} else {
					s.tileMapped.Store(tileInMemory)
				}
			}
			return t, err
		}
	}
	s.store = terrain.NewStore(idx, opts)
	s.terrain = StateLoaded
}

// readIndex reads <dir>/index.json through an os.Root, bounded.
func readIndex(dir string) (terrain.Index, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("GROUND_DIR: %w", err)
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(IndexFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IndexFile, err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, terrain.MaxIndexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IndexFile, err)
	}
	if len(data) > terrain.MaxIndexBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", IndexFile, terrain.MaxIndexBytes)
	}
	idx, err := terrain.ParseIndex(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", IndexFile, err)
	}
	return idx, nil
}

// readGeoid loads the grid at path with core's geoid.LoadMapped, refusing
// first a file that is not a regular file or is larger than
// MaxGeoidBytes. The grid answers bit for bit what geoid.Parse's would;
// Grid.Mapped says whether it is a memory map or bytes in memory.
func readGeoid(path string) (*geoid.Grid, error) {
	path = filepath.Clean(path)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("GEOID_FILE: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("GEOID_FILE: not a regular file")
	}
	if fi.Size() > MaxGeoidBytes {
		return nil, fmt.Errorf("GEOID_FILE: larger than %d bytes", MaxGeoidBytes)
	}
	g, err := geoid.LoadMapped(path)
	if err != nil {
		return nil, fmt.Errorf("GEOID_FILE: %w", err)
	}
	return g, nil
}

// Env resolves what zones needs at p: the ground (known, unknown or not
// configured) and the geoid undulation (nil without a geoid). It never
// returns a ground of 0 m for something it does not know (D-04).
func (s *Service) Env(p core.LatLon) zones.Env {
	var env zones.Env
	switch {
	case s.store != nil:
		e, err := s.store.Elevation(p)
		if err != nil || e == nil {
			env.Ground = zones.GroundUnknown
			s.counters.Inc(CounterGroundUnknown)
		} else {
			env.Ground, env.GroundM = zones.GroundKnown, e.ElevationM
			s.counters.Inc(CounterGroundKnown)
		}
	case s.terrain == StateUnavailable:
		env.Ground = zones.GroundUnknown
		s.counters.Inc(CounterGroundUnknown)
		s.counters.Inc(CounterTerrainUnavailable)
	default:
		env.Ground = zones.GroundNotConfigured
		s.counters.Inc(CounterGroundNotConfigured)
	}
	if n, ok := s.undulation(p); ok {
		env.UndulationM = &n
	}
	return env
}

func (s *Service) undulation(p core.LatLon) (float64, bool) {
	if s.grid == nil {
		s.counters.Inc(CounterUndulationNone)
		return 0, false
	}
	n, err := s.grid.UndulationM(p)
	if err != nil {
		s.counters.Inc(CounterGeoidFailed)
		s.counters.Inc(CounterUndulationNone)
		return 0, false
	}
	return n, true
}

// Elevation is the ground at p with its dataset and spacing, for a caller
// that shows the number (evidence, WP-17; D-05): nil when it is not
// known or no terrain is loaded.
func (s *Service) Elevation(p core.LatLon) *terrain.Elevation {
	if s.store == nil {
		return nil
	}
	e, err := s.store.Elevation(p)
	if err != nil {
		return nil
	}
	return e
}

// Undulator is the geoid for the Remote ID pipeline (WP-8), or a nil
// interface when none is loaded, so that the pipeline's "no geoid"
// branch runs and no AMSL altitude is published.
func (s *Service) Undulator() geoid.Undulator {
	if s.grid == nil {
		return nil
	}
	return s.grid
}

// Ground is the terrain for the detector (WP-12), or a nil interface when
// no tile index is loaded.
func (s *Service) Ground() terrain.Ground {
	if s.store == nil {
		return nil
	}
	return s.store
}

// Counters are the lookups' counters (E-09).
func (s *Service) Counters() *core.Counters { return s.counters }

// TerrainCounters are the tile cache's counters, or nil without terrain.
func (s *Service) TerrainCounters() *core.Counters {
	if s.store == nil {
		return nil
	}
	return s.store.Counters()
}

// Datasets are the DEM datasets the index names, sorted, without "sea".
func (s *Service) Datasets() []string {
	var out []string
	for _, d := range s.index {
		if d != terrain.SeaDataset && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// GeoidDescription is the grid's own description, "" without one.
func (s *Service) GeoidDescription() string {
	if s.grid == nil {
		return ""
	}
	return s.grid.Description()
}

// GeoidMapped reports whether the loaded grid is a read-only memory map
// of GEOID_FILE (linux and darwin) rather than bytes in memory; false
// without a grid.
func (s *Service) GeoidMapped() bool {
	return s.grid != nil && s.grid.Mapped()
}

// TerrainMapped reports whether the last tile read is a read-only memory
// map of its file; known is false until a tile has been read.
func (s *Service) TerrainMapped() (mapped, known bool) {
	switch s.tileMapped.Load() {
	case tileMappedFile:
		return true, true
	case tileInMemory:
		return false, true
	}
	return false, false
}

// Problems lists the inputs that cannot be used and what is therefore
// not judged (Z-09). Empty when terrain and geoid are both loaded.
func (s *Service) Problems() []Problem {
	var out []Problem
	if !s.o.GeoidOnly && s.terrain != StateLoaded {
		out = append(out, Problem{Input: InputTerrain, State: s.terrain, Reason: s.terrainWhy,
			Effect: "AGL zone limits are not judged (limit_not_judged) and the height limit is not evaluated"})
	}
	if s.geoid != StateLoaded {
		out = append(out, Problem{Input: InputGeoid, State: s.geoid, Reason: s.geoidWhy,
			Effect: "no AMSL altitude from a geodetic (HAE) one: such aircraft are not judged vertically, and WGS84 zone limits are not judged"})
	}
	return out
}

// StatusAttrs are the status-line attributes (E-09, SC-22): the state of
// each input, the datasets and their attribution, the tile cache and the
// retry interval, the geoid's description, and whether the grid and the
// last tile read are memory-mapped (geoid_mapped, terrain_mapped; the
// latter only once a tile has been read).
func (s *Service) StatusAttrs() []slog.Attr {
	var out []slog.Attr
	if !s.o.GeoidOnly {
		out = append(out, slog.String("terrain", s.terrain))
		if s.store != nil {
			out = append(out,
				slog.Any("terrain_datasets", s.Datasets()),
				slog.Int("terrain_cells", len(s.index)),
				slog.Int("terrain_tiles_cached", len(s.store.Cached())),
				slog.Float64("terrain_retry_after_s", s.retryAfter.Seconds()),
				slog.String("terrain_attribution", terrain.Attribution))
			if mapped, known := s.TerrainMapped(); known {
				out = append(out, slog.Bool("terrain_mapped", mapped))
			}
		}
	}
	out = append(out, slog.String("geoid", s.geoid))
	if s.grid != nil {
		out = append(out, slog.String("geoid_description", s.grid.Description()),
			slog.Bool("geoid_mapped", s.grid.Mapped()))
	}
	return out
}

// Log writes the start line of the ground (Info when everything is
// loaded) and one warning per problem, naming what is not judged.
func (s *Service) Log(l *slog.Logger) {
	attrs := s.StatusAttrs()
	args := make([]any, 0, len(attrs))
	for _, a := range attrs {
		args = append(args, a)
	}
	l.Info("ground datasets", args...)
	for _, p := range s.Problems() {
		pa := []any{slog.String("input", p.Input), slog.String("state", p.State), slog.String("effect", p.Effect)}
		if p.Reason != "" {
			pa = append(pa, slog.String("reason", p.Reason))
		}
		l.Warn(p.Input+" "+p.State+": "+p.Effect, pa...)
	}
}
