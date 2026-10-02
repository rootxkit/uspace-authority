package ground

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/terrain"
)

// update rewrites testdata/ from the generators below:
//
//	go test ./internal/ground -run TestTestdataIsGenerated -update
var update = flag.Bool("update", false, "rewrite internal/ground/testdata from the generators")

// headerLine is one "# Key Value" comment of a PGM header.
type headerLine struct{ key, value string }

// encodePGM writes a binary PGM (P5) with 16-bit big-endian samples and
// "# Key Value" comment lines, the layout core's internal/pgm.Encode
// writes and pgm.Parse reads (uspace-core v1.2.0 internal/pgm/pgm.go:
// "P5\n", one "# <key> <value>\n" per header line, "<w> <h>\n65535\n",
// then the samples high byte first). Every file it writes is read back
// by core's terrain.ParseTile or geoid.Parse in TestTestdataParses, so
// the layout is pinned by core, not by this function.
func encodePGM(width, height int, header []headerLine, samples []uint16) []byte {
	var b bytes.Buffer
	b.WriteString("P5\n")
	for _, h := range header {
		b.WriteString("# " + h.key + " " + h.value + "\n")
	}
	b.WriteString(strconv.Itoa(width) + " " + strconv.Itoa(height) + "\n65535\n")
	for _, v := range samples {
		b.WriteByte(byte(v >> 8))
		b.WriteByte(byte(v))
	}
	return b.Bytes()
}

// syntheticGeoid is terrain_geoid.json's synthetic grid: 36 x 19 at 10
// deg, Offset -100, Scale 0.01, sample(row, col) = 1000 + 100*row + col,
// row 0 = 90N, col 0 = 0E.
func syntheticGeoid() []byte {
	s := make([]uint16, 36*19)
	for r := range 19 {
		for c := range 36 {
			s[r*36+c] = uint16(1000 + 100*r + c)
		}
	}
	return encodePGM(36, 19, []headerLine{
		{"Description", "synthetic test grid (terrain_geoid.json)"}, {"Offset", "-100"}, {"Scale", "0.01"},
	}, s)
}

// constantGeoidM is the undulation of constantGeoid everywhere.
const constantGeoidM = 15.9

// constantGeoid is a grid with N = 15.9 m everywhere (Tbilisi's EGM2008
// value, rounded), for process tests that need a geoid file.
func constantGeoid() []byte {
	return encodePGM(36, 19, []headerLine{
		{"Description", "constant test grid, N = 15.9 m"}, {"Offset", "15.9"}, {"Scale", "0.01"},
	}, make([]uint16, 36*19))
}

// tileBytes writes a tile in the lab tool's format (terrain.OffsetM,
// terrain.ScaleM, terrain.NoData).
func tileBytes(width, height int, latFirst, lonFirst, step float64, dataset string,
	elevationM func(r, c int) float64, nodata map[[2]int]bool,
) []byte {
	s := make([]uint16, width*height)
	for r := range height {
		for c := range width {
			if nodata[[2]int{r, c}] {
				s[r*width+c] = terrain.NoData
				continue
			}
			s[r*width+c] = uint16((elevationM(r, c) - terrain.OffsetM) / terrain.ScaleM)
		}
	}
	f := func(x float64) string { return strconv.FormatFloat(x, 'g', -1, 64) }
	return encodePGM(width, height, []headerLine{
		{"Description", "synthetic test tile"}, {"Dataset", dataset},
		{"Offset", "-500.0"}, {"Scale", "0.2"}, {"Nodata", "65535"},
		{"LatFirst", f(latFirst)}, {"LonFirst", f(lonFirst)}, {"LatStep", f(step)}, {"LonStep", f(step)},
	}, s)
}

// syntheticTile is terrain_geoid.json's synthetic tile: 5 x 5 at 0.25
// deg, first sample 42.0N 44.0E, rows south, elevation = 400 + 10*row +
// col, sample (1, 1) nodata. It covers cell N41E044.
func syntheticTile() []byte {
	return tileBytes(5, 5, 42, 44, 0.25, "COP-DEM GLO-30",
		func(r, c int) float64 { return float64(400 + 10*r + c) }, map[[2]int]bool{{1, 1}: true})
}

// The ground volume in testdata/tiles exercises every answer:
//
//	N41E044  the synthetic tile: known, and nodata around sample (1, 1)
//	N40E044  "sea": 0 m, no tile read
//	N41E045  listed, the file is not a tile: unreadable
//	N42E044  listed, no file: missing
//	anything else, e.g. N43E044: not in the index, unknown
const testIndex = `{"cells": {
  "N41E044": "COP-DEM GLO-30",
  "N40E044": "sea",
  "N41E045": "COP-DEM GLO-30",
  "N42E044": "COP-DEM GLO-30"
}}
`

// testdataFiles are the generated files under testdata/.
func testdataFiles() map[string][]byte {
	return map[string][]byte{
		"geoid-synthetic.pgm":   syntheticGeoid(),
		"geoid-constant.pgm":    constantGeoid(),
		"tiles/index.json":      []byte(testIndex),
		"tiles/N41E044.pgm":     syntheticTile(),
		"tiles/N41E045.pgm":     []byte("P5\nthis is not a tile\n"),
		"geoid-not-a-grid.pgm":  []byte("P2\n2 3\n"),
		"tiles-bad/index.json":  []byte(`{"N41E044": ""}`),
		"tiles-bad/N41E044.pgm": syntheticTile(),
	}
}

// The committed testdata is what the generators write (small: under 2 kB
// each); -update rewrites it.
func TestTestdataIsGenerated(t *testing.T) {
	for name, want := range testdataFiles() {
		path := filepath.Join("testdata", filepath.FromSlash(name))
		if *update {
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with -update)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from its generator (run with -update)", name)
		}
		if len(got) > 2048 {
			t.Errorf("%s is %d bytes; testdata stays small", name, len(got))
		}
	}
}

// Core reads what encodePGM writes: the layout is core's.
func TestTestdataParses(t *testing.T) {
	for _, b := range [][]byte{syntheticGeoid(), constantGeoid()} {
		if _, err := geoid.Parse(b); err != nil {
			t.Fatalf("geoid.Parse: %v", err)
		}
	}
	tile, err := terrain.ParseTile(syntheticTile())
	if err != nil {
		t.Fatalf("terrain.ParseTile: %v", err)
	}
	if tile.Dataset() != "COP-DEM GLO-30" {
		t.Errorf("dataset %q", tile.Dataset())
	}
	if _, err := terrain.ParseTile([]byte("P5\nthis is not a tile\n")); err == nil {
		t.Error("the unreadable tile parses")
	}
}
