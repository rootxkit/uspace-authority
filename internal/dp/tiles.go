package dp

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/geodesy"
)

// Box is a latitude/longitude box in WGS84 degrees (geodesy.BBox). A
// view or a tile never crosses the antimeridian: such a view is refused
// where it is read (CheckBox).
type Box = geodesy.BBox

// CheckBox refuses a box that is not a usable view: a non-finite edge,
// a latitude outside [-90, 90] or a longitude outside [-180, 180], an
// empty box, or one that crosses the antimeridian.
func CheckBox(b Box) error {
	for _, v := range []float64{b.MinLat, b.MinLon, b.MaxLat, b.MaxLon} {
		if !core.IsFinite(v) {
			return core.Fieldf("bbox", "not a finite number")
		}
	}
	switch {
	case b.MinLat < -90 || b.MaxLat > 90:
		return core.Fieldf("bbox", "latitudes must be in [-90, 90]")
	case b.MinLon < -180 || b.MaxLon > 180:
		return core.Fieldf("bbox", "longitudes must be in [-180, 180]")
	case b.MinLat >= b.MaxLat:
		return core.Fieldf("bbox", "south must be below north")
	case b.MinLon >= b.MaxLon:
		return core.Fieldf("bbox", "west must be below east (a view never crosses the antimeridian)")
	}
	return nil
}

// DiagonalKM is the geodesic length of the box's diagonal, from its
// south-west to its north-east corner, in kilometres (the F3411 display
// area limit is a diagonal, NetMaxDisplayAreaDiagonalKm). Vincenty's
// inverse is uspace-core's; where it does not converge (never for a box
// of a few kilometres) the haversine distance stands in.
func DiagonalKM(b Box) float64 {
	sw, ne := core.LatLon{LatDeg: b.MinLat, LonDeg: b.MinLon}, core.LatLon{LatDeg: b.MaxLat, LonDeg: b.MaxLon}
	d, err := geodesy.DistanceM(sw, ne)
	if err != nil {
		d = geodesy.HaversineM(sw, ne)
	}
	return d / 1000
}

// Tile is one box the Display Provider discovers ISAs for, subscribes
// to and polls. Depth counts the splits after a 413 (0 for a tile of
// the view grid).
type Tile struct {
	Box   Box
	Depth int
}

// Key names the tile: its corners at 1e-7 degrees (F3411's position
// resolution) and its depth. Two views covering the same ground share
// tiles only when their grids coincide; a flight seen in two tiles is
// one flight all the same (the flight memory is per provider and flight
// id).
func (t Tile) Key() string {
	f := func(v float64) string { return strconv.FormatInt(int64(math.Round(v/f3411.MinPositionResolution)), 10) }
	return strings.Join([]string{f(t.Box.MinLat), f(t.Box.MinLon), f(t.Box.MaxLat), f(t.Box.MaxLon), strconv.Itoa(t.Depth)}, ":")
}

// Split4 is t's four quarters, one level deeper.
func (t Tile) Split4() [4]Tile {
	b := t.Box
	midLat, midLon := (b.MinLat+b.MaxLat)/2, (b.MinLon+b.MaxLon)/2
	d := t.Depth + 1
	return [4]Tile{
		{Box: Box{MinLat: b.MinLat, MinLon: b.MinLon, MaxLat: midLat, MaxLon: midLon}, Depth: d},
		{Box: Box{MinLat: b.MinLat, MinLon: midLon, MaxLat: midLat, MaxLon: b.MaxLon}, Depth: d},
		{Box: Box{MinLat: midLat, MinLon: b.MinLon, MaxLat: b.MaxLat, MaxLon: midLon}, Depth: d},
		{Box: Box{MinLat: midLat, MinLon: midLon, MaxLat: b.MaxLat, MaxLon: b.MaxLon}, Depth: d},
	}
}

// maxGridSide bounds the grid of one view (E-10): a view needing more
// than maxGridSide x maxGridSide tiles is cut at the bound and the rest
// counted by the caller.
const maxGridSide = 64

// TilesOf covers b with an n x m grid of equal tiles whose diagonal is
// at most maxKM, with the fewest rows and columns that achieve it, and
// returns at most maxTiles of them (south-west first) and how many it
// left out. A box that already fits is one tile.
func TilesOf(b Box, maxKM float64, maxTiles int) ([]Tile, int) {
	if maxKM <= 0 || maxTiles <= 0 {
		return nil, 0
	}
	rows, cols := 1, 1
	for {
		cell := Box{MinLat: b.MinLat, MinLon: b.MinLon, MaxLat: b.MinLat + (b.MaxLat-b.MinLat)/float64(rows), MaxLon: b.MinLon + (b.MaxLon-b.MinLon)/float64(cols)}
		// The northern row is the widest in metres near the equator and
		// the southern one in the southern hemisphere: check both.
		top := Box{MinLat: b.MaxLat - (b.MaxLat-b.MinLat)/float64(rows), MinLon: cell.MinLon, MaxLat: b.MaxLat, MaxLon: cell.MaxLon}
		if (DiagonalKM(cell) <= maxKM && DiagonalKM(top) <= maxKM) || (rows >= maxGridSide && cols >= maxGridSide) {
			break
		}
		// Split the side that is longer on the ground.
		ns, _ := geodesy.LocalOffsetAboutMidLatM(core.LatLon{LatDeg: cell.MinLat, LonDeg: cell.MinLon}, core.LatLon{LatDeg: cell.MaxLat, LonDeg: cell.MinLon})
		_, ew := geodesy.LocalOffsetAboutMidLatM(core.LatLon{LatDeg: cell.MinLat, LonDeg: cell.MinLon}, core.LatLon{LatDeg: cell.MinLat, LonDeg: cell.MaxLon})
		if (math.Abs(ns) >= math.Abs(ew) && rows < maxGridSide) || cols >= maxGridSide {
			rows++
		} else {
			cols++
		}
	}
	total := rows * cols
	n := min(total, maxTiles)
	out := make([]Tile, 0, n)
	dLat, dLon := (b.MaxLat-b.MinLat)/float64(rows), (b.MaxLon-b.MinLon)/float64(cols)
	for r := 0; r < rows && len(out) < n; r++ {
		for c := 0; c < cols && len(out) < n; c++ {
			t := Box{MinLat: b.MinLat + float64(r)*dLat, MinLon: b.MinLon + float64(c)*dLon, MaxLat: b.MinLat + float64(r+1)*dLat, MaxLon: b.MinLon + float64(c+1)*dLon}
			if r == rows-1 {
				t.MaxLat = b.MaxLat
			}
			if c == cols-1 {
				t.MaxLon = b.MaxLon
			}
			out = append(out, Tile{Box: t})
		}
	}
	return out, total - n
}

// Intersects reports whether a and b share any point.
func Intersects(a, b Box) bool {
	return a.MinLat <= b.MaxLat && b.MinLat <= a.MaxLat && a.MinLon <= b.MaxLon && b.MinLon <= a.MaxLon
}

// Contains reports whether p lies in b, edges included.
func Contains(b Box, p core.LatLon) bool {
	return p.LatDeg >= b.MinLat && p.LatDeg <= b.MaxLat && p.LonDeg >= b.MinLon && p.LonDeg <= b.MaxLon
}

func coord(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// ViewParam is the box as the `view` of GET /uss/flights and of the
// observation interface: "lat1,lng1,lat2,lng2", two opposite corners
// (api/clients/dss-rid.yaml searchFlights).
func ViewParam(b Box) string {
	return coord(b.MinLat) + "," + coord(b.MinLon) + "," + coord(b.MaxLat) + "," + coord(b.MaxLon)
}

// AreaParam is the box as a GeoPolygonString, "lat1,lng1,lat2,lng2,
// lat3,lng3,...", its four corners (api/clients/dss-rid.yaml
// GeoPolygonString).
func AreaParam(b Box) string {
	return strings.Join([]string{
		coord(b.MinLat), coord(b.MinLon), coord(b.MinLat), coord(b.MaxLon),
		coord(b.MaxLat), coord(b.MaxLon), coord(b.MaxLat), coord(b.MinLon),
	}, ",")
}

// ParseView reads "lat1,lng1,lat2,lng2" (two opposite corners) into the
// box they bound. A malformed view is a *core.FieldError naming field;
// it never panics.
func ParseView(s, field string) (Box, error) {
	if len(s) > 256 {
		return Box{}, core.Fieldf(field, "longer than 256 characters")
	}
	parts := strings.Split(s, ",")
	if len(parts) != 4 {
		return Box{}, core.Fieldf(field, "must be lat1,lng1,lat2,lng2")
	}
	var v [4]float64
	for i, p := range parts {
		f, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || !core.IsFinite(f) {
			return Box{}, core.Fieldf(field, "item %d is not a number", i+1)
		}
		v[i] = f
	}
	b := Box{MinLat: math.Min(v[0], v[2]), MaxLat: math.Max(v[0], v[2]), MinLon: math.Min(v[1], v[3]), MaxLon: math.Max(v[1], v[3])}
	if err := CheckBox(b); err != nil {
		reason := err.Error()
		var fe *core.FieldError
		if errors.As(err, &fe) {
			reason = fe.Reason
		}
		return Box{}, core.Fieldf(field, "%s", reason)
	}
	return b, nil
}

// Volume is the box as the extents of a DSS subscription between start
// and end: its outline polygon (no altitude bounds: every height) and
// the time window (RFC3339).
func Volume(b Box, start, end time.Time) f3411.Volume4D {
	poly := f3411.Polygon{Vertices: []f3411.LatLngPoint{
		{Lat: b.MinLat, Lng: b.MinLon}, {Lat: b.MinLat, Lng: b.MaxLon},
		{Lat: b.MaxLat, Lng: b.MaxLon}, {Lat: b.MaxLat, Lng: b.MinLon},
	}}
	return f3411.Volume4D{
		TimeStart: &f3411.Time{Format: f3411.RFC3339, Value: start.UTC()},
		TimeEnd:   &f3411.Time{Format: f3411.RFC3339, Value: end.UTC()},
		Volume:    f3411.Volume3D{OutlinePolygon: &poly},
	}
}

// ParseTileKey reads a Tile.Key back.
func ParseTileKey(key string) (Tile, bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 5 {
		return Tile{}, false
	}
	var v [4]float64
	for i := range 4 {
		n, err := strconv.ParseInt(parts[i], 10, 64)
		if err != nil {
			return Tile{}, false
		}
		v[i] = float64(n) * f3411.MinPositionResolution
	}
	d, err := strconv.Atoi(parts[4])
	if err != nil || d < 0 {
		return Tile{}, false
	}
	return Tile{Box: Box{MinLat: v[0], MinLon: v[1], MaxLat: v[2], MaxLon: v[3]}, Depth: d}, true
}

func nan() float64 { return math.NaN() }
