package scenarios

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-12 (zone applicability windows in flight, Z-12) and the
// reconfigured clear: an aircraft hovers at 520.1 m AMSL where a
// PROHIBITED zone of 450-650 m AMSL is projected with a window that has
// ended: nothing is raised for the samples inside. (utm flew 685.1 m in
// a 600-800 m zone; over the synthetic DEM's 427 m that is 258 m over
// the ground and would raise height_120m, so the band is moved down
// with the aircraft, keeping it inside the band and under 120 m.) The zone is published
// again, permanent, as version 2: critical, raised within the refresh. A
// CONDITIONAL zone of 450-650 m AMSL over the same point is added: a
// warning for it. Both are withdrawn while the aircraft is still inside:
// both clear reconfigured (the zone set changed and the last sample no
// longer raises them), never resolved.
func TestScenarioSC12WindowsAndAZoneWithdrawnInFlight(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-12"})
	s.Seed(seed("sc12.json"))
	now := time.Now().UTC()
	z := ltest.Zone{ID: "SC12P", Type: "PROHIBITED", LatDeg: 41.39, LonDeg: 44.66, HalfSideDeg: 0.0015, LowerM: 450, UpperM: 650,
		ValidFrom: now.Add(-35 * 24 * time.Hour), ValidTo: now.Add(-5 * 24 * time.Hour)}
	s.PublishZones(z)
	ri := standard(t, s)
	rx := s.NewReceiver(s.ReceiverID("rx-sc12"), z.LatDeg, z.LonDeg-0.01, ri)
	ac := &ltest.Aircraft{Transmitter: mac(0xC03), Serial: "TESTSC1200003", OperatorID: "GEOTEST00001201", System: true,
		Path: ltest.Hold(z.LatDeg, z.LonDeg, 520.1)}
	f := rx.Fly(ac)

	// Run 2: the window has ended; 20 samples inside raise nothing.
	f.WaitSteps(20)
	if v := s.Open(violation.KindZoneIncursion, ac.TrackID()); v != nil {
		t.Fatalf("a zone out of its window raised %s", v.ID)
	}
	if n := len(s.Rec.Tracks(ac.TrackID())); n < 18 {
		t.Fatalf("%d tracks during run 2: the absence proves nothing", n)
	}

	// Run 3: permanent again, as version 2.
	z.ValidFrom, z.ValidTo, z.Version = time.Time{}, time.Time{}, 2
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
		ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "reconfigured").InZone(z.ZoneID()).WithSeverity(core.SeverityCritical),
		ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "reconfigured").InZone(c.ZoneID()).WithSeverity(core.SeverityWarning),
	)
	s.CheckIdentity(ri, true)
}
