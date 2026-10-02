package dp

import (
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/f3411"
)

// A view within the display diagonal is one tile; a wider one is cut
// into tiles each within it, covering the view exactly.
func TestTilesOfCutsAViewIntoTilesWithinTheDiagonal(t *testing.T) {
	one, over := TilesOf(box2km, f3411.NetMaxDisplayAreaDiagonalKm, 64)
	if len(one) != 1 || over != 0 || one[0].Box != box2km {
		t.Fatalf("a fitting view: %v over %d", one, over)
	}
	wide := Box{MinLat: 41.6, MinLon: 44.7, MaxLat: 41.8, MaxLon: 44.95} // about 28 km
	tiles, over := TilesOf(wide, f3411.NetMaxDisplayAreaDiagonalKm, 1000)
	if over != 0 || len(tiles) < 4 {
		t.Fatalf("%d tiles, %d over", len(tiles), over)
	}
	area := 0.0
	for _, tl := range tiles {
		if d := DiagonalKM(tl.Box); d > f3411.NetMaxDisplayAreaDiagonalKm {
			t.Errorf("tile %v has a diagonal of %.2f km", tl.Box, d)
		}
		if tl.Box.MinLat < wide.MinLat || tl.Box.MaxLat > wide.MaxLat || tl.Box.MinLon < wide.MinLon || tl.Box.MaxLon > wide.MaxLon {
			t.Errorf("tile %v outside the view", tl.Box)
		}
		area += (tl.Box.MaxLat - tl.Box.MinLat) * (tl.Box.MaxLon - tl.Box.MinLon)
	}
	want := (wide.MaxLat - wide.MinLat) * (wide.MaxLon - wide.MinLon)
	if d := area - want; d > 1e-9 || d < -1e-9 {
		t.Errorf("tiles cover %.9f square degrees, the view %.9f", area, want)
	}
}

// E-10: the tile bound cuts the grid and says how many it left out; at
// the bound nothing is left out.
func TestTilesOfBoundIsCounted(t *testing.T) {
	wide := Box{MinLat: 41.6, MinLon: 44.7, MaxLat: 41.8, MaxLon: 44.95}
	all, _ := TilesOf(wide, f3411.NetMaxDisplayAreaDiagonalKm, 1000)
	cut, over := TilesOf(wide, f3411.NetMaxDisplayAreaDiagonalKm, 3)
	if len(cut) != 3 || over != len(all)-3 {
		t.Fatalf("cut %d over %d of %d", len(cut), over, len(all))
	}
	exact, over := TilesOf(wide, f3411.NetMaxDisplayAreaDiagonalKm, len(all))
	if len(exact) != len(all) || over != 0 {
		t.Fatalf("at the bound: %d over %d", len(exact), over)
	}
}

// A 413 splits a tile into four quarters one level deeper, covering it;
// the key carries the depth and reads back.
func TestSplit4AndTileKeys(t *testing.T) {
	root := Tile{Box: box7km}
	q := root.Split4()
	for _, c := range q {
		if c.Depth != 1 || !Intersects(c.Box, root.Box) {
			t.Fatalf("quarter %+v", c)
		}
		back, ok := ParseTileKey(c.Key())
		if !ok || back.Depth != 1 || back.Key() != c.Key() {
			t.Fatalf("key %q read back as %+v", c.Key(), back)
		}
	}
	if q[0].Key() == root.Key() || q[0].Box.MaxLat != q[2].Box.MinLat {
		t.Fatal("quarters do not tile the parent")
	}
	for _, bad := range []string{"", "1:2:3:4", "a:b:c:d:0", "1:2:3:4:-1"} {
		if _, ok := ParseTileKey(bad); ok {
			t.Errorf("%q read as a key", bad)
		}
	}
}

// The view and area strings are the contract's forms (dss-rid.yaml:
// lat1,lng1,lat2,lng2; GeoPolygonString lat,lng pairs), and a view reads
// back.
func TestViewAndAreaParams(t *testing.T) {
	b := Box{MinLat: 41.5, MinLon: 44.5, MaxLat: 41.6, MaxLon: 44.75}
	if got := ViewParam(b); got != "41.5,44.5,41.6,44.75" {
		t.Fatalf("view %q", got)
	}
	if got := AreaParam(b); got != "41.5,44.5,41.5,44.75,41.6,44.75,41.6,44.5" {
		t.Fatalf("area %q", got)
	}
	back, err := ParseView("41.6,44.75,41.5,44.5", "view")
	if err != nil || back != b {
		t.Fatalf("parse %v %v", back, err)
	}
}

func TestParseViewRefusesWhatIsNotAView(t *testing.T) {
	for _, s := range []string{"", "1,2,3", "a,b,c,d", "91,0,92,1", "0,0,0,1", "1,179,2,181", "NaN,0,1,1", strings.Repeat("1", 300)} {
		if _, err := ParseView(s, "view"); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if err := CheckBox(Box{MinLat: 1, MinLon: 179, MaxLat: 2, MaxLon: -179}); err == nil {
		t.Error("a box across the antimeridian accepted")
	}
}

// E-03: the subscription extents are the contract's Volume4D, with an
// outline polygon of the four corners and RFC3339 times; core's
// envelope reads them back as the box.
func TestVolumeIsTheBoxInCoreTypes(t *testing.T) {
	v := Volume(box2km, t0, t0.Add(subscriptionDuration))
	box, start, end, err := f3411.Volume4DToZonesEnvelope(v)
	if err != nil || !start.Equal(t0) || !end.Equal(t0.Add(24*60*60*1e9)) {
		t.Fatalf("%v %v %v", start, end, err)
	}
	if box.MinLat > box2km.MinLat || box.MaxLat < box2km.MaxLat || box.MinLon > box2km.MinLon || box.MaxLon < box2km.MaxLon {
		t.Fatalf("envelope %+v does not hold %+v", box, box2km)
	}
}

func FuzzParseView(f *testing.F) {
	f.Add("41.5,44.5,41.6,44.75")
	f.Add("1,2,3")
	f.Add("-90,-180,90,180")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := ParseView(s, "view")
		if err == nil {
			if CheckBox(b) != nil {
				t.Fatalf("%q accepted as %+v", s, b)
			}
		}
	})
}
