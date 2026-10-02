package ground

import (
	"path/filepath"
	"testing"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/zones"
)

// What the detector (WP-12) will see through Env: core judges, this
// test only checks that the Env this package builds leads core to the
// documented answer in each state (Z-09, D-04).

func aglZone(t core.ZoneType) *zones.Zone {
	// 0 to 120 m AGL; JudgeVertical takes the aircraft as horizontally
	// inside already.
	return &zones.Zone{Identifier: "GEO-TEST-1", Country: "GEO", Type: t,
		Upper: &zones.Limit{ValueM: 120, Ref: core.RefAGL}}
}

func aircraft(altAMSLM float64) zones.Aircraft {
	return zones.Aircraft{AltAMSLM: &altAMSLM, AltSource: core.AltGeodetic}
}

// Absence: without a DEM, an AGL limit of a PROHIBITED zone is not
// judged (limit_not_judged, no_terrain) and the height limit is not
// evaluated.
func TestAGLLimitWithoutDEMIsNotJudged(t *testing.T) {
	s := New(Options{})
	env := s.Env(posKnown)
	r := zones.JudgeVertical(aglZone(core.ZoneProhibited), aircraft(500), env, zones.DefaultPolicy())
	if !r.LimitNotJudged || !r.Reasons.Has(zones.ReasonNoTerrain) || r.Raise == nil ||
		r.Raise.Detail.LimitNotJudged == nil || !*r.Raise.Detail.LimitNotJudged {
		t.Fatalf("result %+v", r)
	}
	pol := zones.DefaultPolicy()
	limitM := 120.0
	pol.MaxHeightAGLM = &limitM
	if h := zones.JudgeHeightLimit(aircraft(700), env, pol); !h.NotEvaluated || !h.Reasons.Has(zones.ReasonNoTerrain) {
		t.Fatalf("height %+v", h)
	}
	// Configured terrain whose tile is missing: ground_unknown, the same
	// refusal to judge.
	s = loaded(t, Options{})
	r = zones.JudgeVertical(aglZone(core.ZoneProhibited), aircraft(500), s.Env(posMissing), zones.DefaultPolicy())
	if !r.LimitNotJudged || !r.Reasons.Has(zones.ReasonGroundUnknown) {
		t.Fatalf("missing tile: %+v", r)
	}
}

// Presence: with the DEM the same limit is judged against the ground of
// 423 m: 500 m AMSL is 77 m AGL, inside, a critical raise with the
// height; 600 m AMSL is 177 m AGL, above it, nothing; and the height
// limit raises at 700 m AMSL (277 m AGL).
func TestAGLLimitWithDEMIsJudged(t *testing.T) {
	s := loaded(t, Options{Dir: filepath.Join("testdata", "tiles")})
	env := s.Env(posKnown)
	r := zones.JudgeVertical(aglZone(core.ZoneProhibited), aircraft(500), env, zones.DefaultPolicy())
	if r.LimitNotJudged || r.NotEvaluated || r.Raise == nil || r.Raise.Severity != core.SeverityCritical ||
		r.Raise.Detail.HeightAGLM == nil || *r.Raise.Detail.HeightAGLM != 77 {
		t.Fatalf("inside: %+v", r)
	}
	if r = zones.JudgeVertical(aglZone(core.ZoneProhibited), aircraft(600), env, zones.DefaultPolicy()); r.Raise != nil || r.NotEvaluated || r.LimitNotJudged {
		t.Fatalf("above: %+v", r)
	}
	pol := zones.DefaultPolicy()
	limitM := 120.0
	pol.MaxHeightAGLM = &limitM
	h := zones.JudgeHeightLimit(aircraft(700), env, pol)
	if h.NotEvaluated || h.Raise == nil || *h.Raise.Detail.HeightAGLM != 277 {
		t.Fatalf("height %+v", h)
	}
}

// A WGS84 limit needs the geoid: not judged without it, judged with it.
func TestWGS84LimitNeedsTheGeoid(t *testing.T) {
	z := &zones.Zone{Identifier: "GEO-TEST-2", Country: "GEO", Type: core.ZoneProhibited,
		Upper: &zones.Limit{ValueM: 600, Ref: core.RefWGS84}}
	if r := zones.JudgeVertical(z, aircraft(500), New(Options{}).Env(tbilisi), zones.DefaultPolicy()); !r.Reasons.Has(zones.ReasonNoGeoid) {
		t.Fatalf("no geoid: %+v", r)
	}
	s := New(Options{GeoidFile: filepath.Join("testdata", "geoid-constant.pgm")})
	r := zones.JudgeVertical(z, aircraft(500), s.Env(tbilisi), zones.DefaultPolicy())
	if r.LimitNotJudged || r.Raise == nil || r.Raise.Detail.AltHAEM == nil || *r.Raise.Detail.AltHAEM != 500+constantGeoidM {
		t.Fatalf("with geoid: %+v", r)
	}
}
