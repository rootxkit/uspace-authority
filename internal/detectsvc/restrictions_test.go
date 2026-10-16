package detectsvc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"

	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// memRestrictions is a RestrictionSource holding fixed rows.
type memRestrictions struct{ rows []reader.ProjRestriction }

func (m memRestrictions) LoadRestrictions(context.Context) ([]reader.ProjRestriction, error) {
	return m.rows, nil
}

// servedRestriction is a restriction as the CISP serves it and WP-6
// projects it: one limitedApplicability period [start, end], the
// CISP's block still active. Invented, around Tbilisi.
func servedRestriction(id string, start, end time.Time) []byte {
	s, e := start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339)
	h := 0.001
	return fmt.Appendf(nil, `{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[%g,%g],[%g,%g],[%g,%g],[%g,%g],[%g,%g]]],"layer":{"lower":0,"lowerReference":"AMSL","upper":1500,"upperReference":"AMSL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR","EMERGENCY"],"limitedApplicability":[{"startDateTime":%q,"endDateTime":%q}],"zoneAuthority":[{"name":[{"text":"Test ANSP","lang":"en-GB"}],"purpose":"NOTIFICATION"}],"extendedProperties":{"cis_restriction":{"id":"r-%s","ansp_ref":"TEST-DAR-1","ansp_version":1,"state":"active","starts_at":%q,"ends_at":%q,"ended_by":null,"uspace_airspace_id":"TSU001"}}}}`,
		zLon-h, zLat-h, zLon+h, zLat-h, zLon+h, zLat+h, zLon-h, zLat+h, zLon-h, zLat-h, id, s, e, id, s, e)
}

// Plan test 8, the defence the expiry rule leaves in place: the
// restriction's own window ends it for the detectors, whether or not the
// CISP's expiry version has arrived. The projection still holds the
// restriction active (the expiry not yet installed, or held); an
// aircraft inside it before its signed end raises zone_incursion, the
// same aircraft after the end clears resolved, and one that enters only
// after the end raises nothing (E-01).
func TestRestrictionPastItsSignedEndStopsApplyingWithoutTheExpiry(t *testing.T) {
	end := t0.Add(30 * time.Second)
	src := memRestrictions{rows: []reader.ProjRestriction{{
		Identifier: "DAR0001", Feature: servedRestriction("DAR0001", t0.Add(-time.Hour), end), State: "active", CisVersion: 2,
	}}}
	rr := &RestrictionReader{Source: src, Daylight: ed318.NOAADaylight{}, Counters: &core.Counters{}, Now: func() time.Time { return t0 }}
	if err := rr.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	zs, _, loaded, notJudged := rr.Set()
	if !loaded || len(zs) != 1 || len(notJudged) != 0 {
		t.Fatalf("restriction not held for judgement: %d zones, loaded %v, not judged %v", len(zs), loaded, notJudged)
	}
	if !zs[0].AppliesAt(end) || zs[0].AppliesAt(end.Add(time.Second)) {
		t.Fatal("the restriction's window is not its signed limitedApplicability")
	}

	r := newRig(t, nil)
	r.in.setPolicy(1, nil)
	r.in.setZones(zs...)
	inside := func(id string) sample { return sample{id: id, lat: zLat, lon: zLon, altAMSL: f64(500)} }
	r.at(0, inside("A"))
	r.tick(1)
	if got := transitions(byKind(r.pub.take(), violation.KindZoneIncursion, "A"), false); len(got) != 1 || got[0].Body.State != violation.StateRaised {
		t.Fatalf("inside the restriction before its end: %s", describe(got))
	}
	// Past the end, the projection unchanged: A clears, B never raises.
	var ms []*violation.Message
	for i := 0; i <= 10; i++ {
		sec := 40 + float64(i)
		r.at(sec, inside("A"), inside("B"))
		r.tick(sec + 0.5)
		ms = append(ms, r.pub.take()...)
	}
	a := transitions(byKind(ms, violation.KindZoneIncursion, "A"), false)
	if len(a) != 1 || a[0].Body.State != violation.StateCleared || a[0].Body.ClearReason == nil || *a[0].Body.ClearReason != "resolved" {
		t.Fatalf("A past the restriction's end: %s", describe(a))
	}
	if b := byKind(ms, violation.KindZoneIncursion, "B"); len(b) != 0 {
		t.Fatalf("B entered after the restriction's end: %s", describe(b))
	}
}
