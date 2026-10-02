package ground

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/ed318"
)

// Published times for Tbilisi (41.7151 N, 44.8271 E), UTC, from the
// sunrise-sunset.org API (https://api.sunrise-sunset.org/json?lat=41.7151
// &lng=44.8271&date=<date>&formatted=0), retrieved 2026-10-02: sunrise,
// sunset, civil_twilight_begin (BMCT) and civil_twilight_end (EECT). The
// US Naval Observatory's API was not reachable from the development
// network that day. WP-11 asks for agreement within 2 minutes.
var tbilisiPublished = map[string]map[string]string{
	"2026-06-21": {
		ed318.EventBMCT: "2026-06-21T00:52:01Z", ed318.EventSR: "2026-06-21T01:24:34Z",
		ed318.EventSS: "2026-06-21T16:40:24Z", ed318.EventEECT: "2026-06-21T17:12:58Z",
	},
	"2026-12-21": {
		ed318.EventBMCT: "2026-12-21T03:52:46Z", ed318.EventSR: "2026-12-21T04:22:40Z",
		ed318.EventSS: "2026-12-21T13:34:43Z", ed318.EventEECT: "2026-12-21T14:04:36Z",
	},
}

func TestDaylightAtTbilisiAgreesWithPublishedTimes(t *testing.T) {
	const tol = 2 * time.Minute
	dl := Daylight()
	for date, events := range tbilisiPublished {
		day, err := time.Parse(time.DateOnly, date)
		if err != nil {
			t.Fatal(err)
		}
		for name, published := range events {
			want, err := time.Parse(time.RFC3339, published)
			if err != nil {
				t.Fatal(err)
			}
			got, err := dl.Event(name, day, tbilisi)
			if err != nil {
				t.Fatalf("%s %s: %v", date, name, err)
			}
			if d := got.Sub(want).Abs(); d > tol {
				t.Errorf("%s %s: %s, published %s (off by %s)", date, name, got.UTC().Format(time.RFC3339), published, d)
			}
		}
	}
}

// Absence of an event is an error, never a time: no sunset at 80 N at
// midsummer.
func TestDaylightWithoutTheEventIsAnError(t *testing.T) {
	day := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	if _, err := Daylight().Event(ed318.EventSS, day, tbilisi); err != nil {
		t.Fatalf("Tbilisi has a sunset: %v", err)
	}
	svalbard := tbilisi
	svalbard.LatDeg = 80
	if got, err := Daylight().Event(ed318.EventSS, day, svalbard); err == nil {
		t.Fatalf("a sunset at 80 N on 21 June: %v", got)
	}
}
