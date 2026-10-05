package scenarios

import (
	"testing"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/ltest"
)

// WP-25 done-when: one aircraft through a PROHIBITED zone with the
// detector absent. The runner records its tracks end to end (simulated
// receiver, rid-ingest, trk.v1, tsdb-writer, the tracks table) and
// asserts, explicitly, that no violation consumer exists: no detect
// durable on TRK, nothing on ALRT, and no alert of any kind.
func TestScenarioSmokeOneAircraftThroughAZoneWithNoDetector(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "smoke"})
	sd := s.Seed(seed("smoke.json"))
	z := s.ZoneByID(sd, "SMK1")
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)

	rx := s.NewReceiver(s.ReceiverID("rx-smoke"), z.LatDeg, z.LonDeg-0.01, ri)
	legs := []ltest.Leg{
		ltest.Stay(3, outside(z, 520)), ltest.Move(3, outside(z, 520), centre(z, 520)), ltest.Stay(5, centre(z, 520)),
		ltest.Move(3, centre(z, 520), outside(z, 520)), ltest.Stay(3, outside(z, 520)),
	}
	ac := &ltest.Aircraft{Transmitter: mac(1), Serial: "TESTSMK000001", OperatorID: "GEOTEST00002501", System: true, Path: ltest.Legs(legs...)}
	f := rx.Fly(ac)
	f.WaitSteps(ltest.Steps(legs...))
	f.Stop()

	n := ltest.Steps(legs...)
	s.Await("a track for every step", 20e9, func() bool { return len(s.Rec.Tracks(ac.TrackID())) >= n })
	inside := 0
	for _, o := range s.Rec.Tracks(ac.TrackID()) {
		p := o.Msg.Body.Position
		if p.Lat > z.LatDeg-z.HalfSideDeg && p.Lat < z.LatDeg+z.HalfSideDeg && p.Lng > z.LonDeg-z.HalfSideDeg && p.Lng < z.LonDeg+z.HalfSideDeg {
			inside++
		}
		if o.Invalid != "" {
			t.Errorf("a track the schema refuses: %s", o.Invalid)
		}
		if o.Msg.Body.Identification.Status != "registered" {
			t.Errorf("track identified %s, want registered", o.Msg.Body.Identification.Status)
		}
	}
	if inside < 5 {
		t.Fatalf("%d tracks inside the zone, want at least 5: the run proves nothing", inside)
	}
	// No violation consumer, explicitly.
	for _, c := range s.Consumers(bus.StreamTRK) {
		if len(c) >= len("detect_") && c[:len("detect_")] == "detect_" {
			t.Errorf("a detect durable exists on TRK: %s", c)
		}
	}
	if n := s.StreamMessages(bus.StreamALRT); n != 0 {
		t.Errorf("ALRT holds %d messages with no detector running", n)
	}
	s.Verify() // nothing expected: any alert is a false alert
	s.CheckIdentity(ri, true)
	s.Note("tracks_inside_zone", inside)
}
