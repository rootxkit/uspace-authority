package scenarios

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-12 (zone applicability windows in flight, Z-12) and the
// reconfigured clear, utm's lab runs 1-4 in one zone. Run 1: a
// PROHIBITED zone of 450-650 m AMSL is projected permanent and one
// aircraft flies through it at 520.1 m AMSL and out: critical, cleared
// resolved on exit. Run 2: the zone is published again, as version 2,
// with a window that has ended, and a second aircraft hovers inside at
// 520.1 m AMSL: nothing is raised for the samples inside. (utm flew
// 685.1 m in a 600-800 m zone; over the synthetic DEM's 427 m that is
// 258 m over the ground and would raise height_120m, so the band is
// moved down with the aircraft, keeping it inside the band and under
// 120 m.) Run 3: the zone is published again, permanent, as version 3:
// critical, raised within the refresh. Run 4: a CONDITIONAL zone of
// 450-650 m AMSL over the same point is added: a warning for it. Both
// are withdrawn while the aircraft is still inside: both clear
// reconfigured (the zone set changed and the last sample no longer
// raises them), never resolved.
func TestScenarioSC12WindowsAndAZoneWithdrawnInFlight(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-12"})
	s.Seed(seed("sc12.json"))
	z := ltest.Zone{ID: "SC12P", Type: "PROHIBITED", LatDeg: 41.39, LonDeg: 44.66, HalfSideDeg: 0.0015, LowerM: 450, UpperM: 650}
	s.PublishZones(z)
	ri := standard(t, s)
	rx := s.NewReceiver(s.ReceiverID("rx-sc12"), z.LatDeg, z.LonDeg-0.01, ri)

	// Run 1: permanent; through the zone and out, cleared resolved.
	legs := pass(z, 520.1)
	ac1 := &ltest.Aircraft{Transmitter: mac(0xC01), Serial: "TESTSC1200001", OperatorID: "GEOTEST00001201", System: true, Path: ltest.Legs(legs...)}
	f1 := rx.Fly(ac1)
	v1 := s.AwaitRaised(violation.KindZoneIncursion, ac1.TrackID(), 20*time.Second)
	if r := s.AwaitCleared(v1.ID, 20*time.Second); r != "resolved" {
		t.Errorf("run 1 cleared %s on exit, want resolved", r)
	}
	f1.WaitSteps(ltest.Steps(legs...))
	f1.Stop()

	// Run 2: the window has ended; 20 samples inside raise nothing.
	now := time.Now().UTC()
	z.ValidFrom, z.ValidTo, z.Version = now.Add(-35*24*time.Hour), now.Add(-5*24*time.Hour), 2
	s.PublishZones(z)
	ac := &ltest.Aircraft{Transmitter: mac(0xC03), Serial: "TESTSC1200003", OperatorID: "GEOTEST00001201", System: true,
		Path: ltest.Hold(z.LatDeg, z.LonDeg, 520.1)}
	f := rx.Fly(ac)
	f.WaitSteps(20)
	if v := s.Open(violation.KindZoneIncursion, ac.TrackID()); v != nil {
		t.Fatalf("a zone out of its window raised %s", v.ID)
	}
	if n := len(s.Rec.Tracks(ac.TrackID())); n < 18 {
		t.Fatalf("%d tracks during run 2: the absence proves nothing", n)
	}

	// Run 3: permanent again, as version 3.
	z.ValidFrom, z.ValidTo, z.Version = time.Time{}, time.Time{}, 3
	published := time.Now()
	s.PublishZones(z)
	vp := s.AwaitRaised(violation.KindZoneIncursion, ac.TrackID(), 10*time.Second)
	s.Note("published_to_raise_ms", vp.RaisedAt.Sub(published).Milliseconds())

	// Run 4: plus a CONDITIONAL zone over the same point.
	c := ltest.Zone{ID: "SC12C", Type: "CONDITIONAL", LatDeg: z.LatDeg, LonDeg: z.LonDeg, HalfSideDeg: 0.001, LowerM: 450, UpperM: 650}
	s.PublishZones(z, c)
	s.Await("the CONDITIONAL zone's warning", 10*time.Second, func() bool {
		for _, v := range s.Rec.Violations() {
			if v.Track == ac.TrackID() && v.ZoneID == c.ZoneID() && v.ClearedAt.IsZero() {
				return true
			}
		}
		return false
	})

	// Both withdrawn with the aircraft inside: reconfigured.
	s.PublishZones()
	s.Await("both cleared", 10*time.Second, func() bool {
		n := 0
		for _, v := range s.Rec.Violations() {
			if v.Track == ac.TrackID() && !v.ClearedAt.IsZero() {
				n++
			}
		}
		return n == 2
	})
	f.WaitSteps(5)
	f.Stop()
	s.Verify(
		ltest.Raise(violation.KindZoneIncursion, ac1.TrackID(), "resolved").InZone(z.ZoneID()).WithSeverity(core.SeverityCritical),
		ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "reconfigured").InZone(z.ZoneID()).WithSeverity(core.SeverityCritical),
		ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "reconfigured").InZone(c.ZoneID()).WithSeverity(core.SeverityWarning),
	)
	s.CheckIdentity(ri, true)
}
