package cell

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
)

type kvT = jetstream.KeyValue

// The token is the core name with ':' written '_', read back exactly,
// on the points core pins (Tbilisi, both poles, the antimeridian).
func TestTokenRoundTripsCoreNames(t *testing.T) {
	for _, c := range []struct {
		p          core.LatLon
		name5, tok string
	}{
		{core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271}, "c5:1317:2248", "c5_1317_2248"},
		{core.LatLon{LatDeg: 90, LonDeg: 0}, "c5:1799:1800", "c5_1799_1800"},
		{core.LatLon{LatDeg: -90, LonDeg: -180}, "c5:0:0", "c5_0_0"},
		{core.LatLon{LatDeg: 0, LonDeg: 180}, "c5:900:0", "c5_900_0"},
	} {
		id, err := Of(c.p, Level5)
		if err != nil || id.String() != c.name5 || Token(id) != c.tok {
			t.Errorf("%v: %s %s %v", c.p, id, Token(id), err)
			continue
		}
		back, err := ParseToken(c.tok)
		if err != nil || back != id {
			t.Errorf("%s: %v %v", c.tok, back, err)
		}
	}
	c3, c5, err := Tokens(core.LatLon{LatDeg: 41.7151, LonDeg: 44.8271})
	if err != nil || c3 != "c3_131_224" || c5 != "c5_1317_2248" {
		t.Fatalf("%s %s %v", c3, c5, err)
	}
	if _, _, err := Tokens(core.LatLon{LatDeg: 91}); err == nil {
		t.Fatal("an invalid position has tokens")
	}
	if Token(ID{}) != "" {
		t.Fatal("an invalid cell has a token")
	}
}

func TestParseTokenRefusesWhatTokenNeverWrites(t *testing.T) {
	for _, bad := range []string{"", "c5:1317:2248", "c5_1317", "c5_01317_2248", "C5_1317_2248", "c5_1800_0", "c4_1_1", "c5_1317_2248_1"} {
		_, err := ParseToken(bad)
		var fe *core.FieldError
		if !errors.As(err, &fe) || fe.Field != "cell" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if id, err := Parse("c3:131:224"); err != nil || id.Level != Level3 {
		t.Fatal(id, err)
	}
}

// A viewport over Tbilisi: the cover plus one ring of neighbours.
func TestViewportIsTheCoverPlusAOneCellMargin(t *testing.T) {
	b := geodesy.BBox{MinLat: 41.70, MinLon: 44.75, MaxLat: 41.75, MaxLon: 44.85}
	cells, err := Viewport(b, DefaultViewportMax)
	if err != nil {
		t.Fatal(err)
	}
	// The cover is rows 1317 x columns 2247..2248; with the margin rows
	// 1316..1318 x columns 2246..2249.
	if len(cells) != 3*4 {
		t.Fatalf("%d cells: %v", len(cells), cells)
	}
	if cells[0].String() != "c5:1316:2246" || cells[len(cells)-1].String() != "c5:1318:2249" {
		t.Fatalf("%v", cells)
	}
	if !slices.IsSortedFunc(cells, func(a, b ID) int {
		if a.LatIdx != b.LatIdx {
			return a.LatIdx - b.LatIdx
		}
		return a.LonIdx - b.LonIdx
	}) {
		t.Fatal("not sorted")
	}
}

// Across the antimeridian the margin wraps in longitude (core's Ring1).
func TestViewportAcrossTheAntimeridian(t *testing.T) {
	cells, err := Viewport(geodesy.BBox{MinLat: 0.01, MinLon: 179.95, MaxLat: 0.02, MaxLon: -179.95}, DefaultViewportMax)
	if err != nil {
		t.Fatal(err)
	}
	var cols []int
	for _, c := range cells {
		if !slices.Contains(cols, c.LonIdx) {
			cols = append(cols, c.LonIdx)
		}
	}
	slices.Sort(cols)
	if !slices.Equal(cols, []int{0, 1, 3598, 3599}) {
		t.Fatalf("columns %v", cols)
	}
}

// E-10: past the bound, margin included, the viewport is refused naming
// the bound; at it, it passes.
func TestViewportBoundIsExceededAndMet(t *testing.T) {
	b := geodesy.BBox{MinLat: 41.70, MinLon: 44.75, MaxLat: 41.75, MaxLon: 44.85}
	if _, err := Viewport(b, 12); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	_, err := Viewport(b, 11)
	var fe *core.FieldError
	if !errors.As(err, &fe) || fe.Field != "bbox" || !strings.Contains(err.Error(), "11") {
		t.Fatalf("past the bound: %v", err)
	}
	// The cover alone past the bound is refused by core before anything
	// is allocated.
	if _, err := Viewport(geodesy.BBox{MinLat: -10, MinLon: -10, MaxLat: 10, MaxLon: 10}, 100); err == nil {
		t.Fatal("a large box passed")
	}
}

func TestValidateAssignmentsNamesEachFault(t *testing.T) {
	if err := ValidateAssignments(map[string]string{"c3:131:224": "detect-1", "c3:131:225": "detect-2"}); err != nil {
		t.Fatal(err)
	}
	err := ValidateAssignments(map[string]string{"c5:1317:2248": "detect-1", "c3:131:224": "Detect 1", "x": "w"})
	for _, f := range []string{"assignments.c5:1317:2248", "assignments.c3:131:224", "assignments.x"} {
		if err == nil || !strings.Contains(err.Error(), f) {
			t.Errorf("%s not named: %v", f, err)
		}
	}
}

func TestClaimGivesAWorkerItsCellsAndRefusesNone(t *testing.T) {
	o := Ownership{Version: 4, Assignments: map[string]string{"c3:131:225": "detect-1", "c3:131:224": "detect-1", "c3:132:224": "detect-2", "bad": "detect-1"}}
	c, err := ClaimFor(o, true, "detect-1", false)
	if err != nil || len(c.Cells) != 2 || c.Cells[0].String() != "c3:131:224" || c.Version != 4 || c.All {
		t.Fatalf("%+v %v", c, err)
	}
	c3, _ := Parse("c3:131:225")
	other, _ := Parse("c3:132:224")
	if !c.Owns(c3) || c.Owns(other) {
		t.Fatal("Owns")
	}
	// E-01 pair: a worker with no cell, and no map at all, refuse to
	// start; CELLS=all starts either way and owns everything.
	if _, err := ClaimFor(o, true, "detect-9", false); !errors.Is(err, ErrNoCells) || !strings.Contains(err.Error(), "detect-9") {
		t.Fatalf("no cell: %v", err)
	}
	if _, err := ClaimFor(Ownership{}, false, "detect-1", false); !errors.Is(err, ErrNoCells) {
		t.Fatalf("no map: %v", err)
	}
	all, err := ClaimFor(Ownership{}, false, "detect-9", true)
	if err != nil || !all.All || !all.Owns(other) {
		t.Fatalf("%+v %v", all, err)
	}
}

func TestStoreEncodeRefusesAMapPastTheBound(t *testing.T) {
	s := Store{MaxBytes: 200}
	small := Ownership{Version: 1, Assignments: map[string]string{"c3:131:224": "detect-1"}}
	if _, err := s.Encode(small); err != nil {
		t.Fatal(err)
	}
	big := Ownership{Version: 1, Assignments: map[string]string{}}
	for i := range 20 {
		big.Assignments["c3:131:"+string(rune('0'+i%10))+string(rune('0'+i/10))] = "detect-1"
	}
	if _, err := s.Encode(big); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "200") {
		t.Fatalf("%v", err)
	}
}

// With CELLS=all nothing is read; with the map unreadable the worker
// does not guess after its attempts.
func TestLoadClaimReadsOrRefuses(t *testing.T) {
	unreachable := Store{Open: nil}
	c, err := LoadClaim(context.Background(), unreachable, "detect-1", true, 3, time.Millisecond)
	if err != nil || !c.All {
		t.Fatalf("%+v %v", c, err)
	}
	calls := 0
	failing := Store{Open: func(context.Context) (kvT, error) { calls++; return nil, errors.New("bus down") }}
	if _, err := LoadClaim(context.Background(), failing, "detect-1", false, 3, time.Millisecond); err == nil || calls != 3 ||
		!strings.Contains(err.Error(), "3 attempts") {
		t.Fatalf("%v after %d calls", err, calls)
	}
}
