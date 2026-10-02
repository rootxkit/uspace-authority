package zonesvc

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/ed318"
)

// sunriseToSunset is a zone in force from sunrise to sunset every day of
// the week around testNow; feature puts it at Tbilisi (41.7 N, 44.8 E).
const sunriseToSunset = `[{"startDateTime":"2026-10-01T00:00:00Z","endDateTime":"2026-10-08T00:00:00Z","schedule":[{"day":["ANY"],"startEvent":"SR","endEvent":"SS"}]}]`

func draftSunrise(t *testing.T, s *Service) {
	t.Helper()
	if _, err := s.Draft(context.Background(), DatasetZones, draftIn(feature(zoneOpts{identifier: "DAY001", limited: sunriseToSunset})), true, inspector); err != nil {
		t.Fatal(err)
	}
}

// Assemble wires the ground package's daylight, core's NOAA calculator,
// not a stub.
func TestAssembleWiresGroundDaylight(t *testing.T) {
	p, err := Assemble(Setup{Meta: Meta{ProviderName: "Test authority", ProviderLang: "en-GB"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Service.Daylight.(ed318.NOAADaylight); !ok {
		t.Fatalf("Daylight is %T, want ed318.NOAADaylight", p.Service.Daylight)
	}
}

// With daylight available, a sunrise-scheduled zone is answered from its
// position: on 2026-10-05 at Tbilisi the sun rises near 03:00 UTC and
// sets near 14:40 UTC.
func TestSunriseZoneResolvesWithGroundDaylight(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	s.Daylight = nil // the default: ground.Daylight
	draftSunrise(t, s)
	day := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		at   time.Time
		want Applicability
	}{
		{day.Add(12 * time.Hour), Applies},
		{day.Add(1 * time.Hour), NotApplicable},
		{day.Add(20 * time.Hour), NotApplicable},
	} {
		a, err := s.Applies(ctx, "DAY001", 0, c.at)
		if err != nil || a.Answer != c.want || a.Reason != "" {
			t.Errorf("%s: %v %+v, want %s", c.at, err, a, c.want)
		}
	}
	if n := s.Counters.Get(CounterDaylightUnavailable); n != 0 {
		t.Fatalf("daylight_unavailable counted %d times", n)
	}
}

// Without a daylight source the same question is refused 503
// daylight_unavailable and counted, never guessed.
func TestSunriseZoneRefusedWithoutDaylight(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newService(t)
	s.Daylight = NoDaylight{}
	draftSunrise(t, s)
	_, err := s.Applies(ctx, "DAY001", 0, testNow)
	if p := problemOf(t, err); p.Status != http.StatusServiceUnavailable || p.Slug() != SlugDaylight {
		t.Fatalf("%+v", p)
	}
	if n := s.Counters.Get(CounterDaylightUnavailable); n != 1 {
		t.Fatalf("daylight_unavailable counted %d times, want 1", n)
	}
}

// The reader's default daylight is the ground package's: a sunrise zone
// is indexed and judged, not named in zones_not_judged.
func TestReaderJudgesSunriseZoneWithGroundDaylight(t *testing.T) {
	src := &fakeSource{rows: []ProjectedRow{
		projected("DAY001", 1, feature(zoneOpts{identifier: "DAY001", limited: sunriseToSunset}), t0, t1),
	}}
	r := &ProjectionReader{Source: src, Counters: &core.Counters{}, Now: func() time.Time { return testNow }}
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if nj := r.NotJudged(); len(nj) != 0 {
		t.Fatalf("not judged: %v", nj)
	}
	if got := candidateTypes(r); len(got) != 1 {
		t.Fatalf("the sunrise zone is indexed: %v", got)
	}
}
