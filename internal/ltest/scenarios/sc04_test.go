package scenarios

import (
	"math"
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-04 (the height limit over the ground, R-07, D-04): a registered
// aircraft holds 100 m over the synthetic DEM, climbs to 200 m over it,
// holds, and comes back down. height_120m is raised once the height over
// the DEM passes the policy's 120 m, with its peak and the DEM dataset,
// and cleared resolved once it has been at or below 120 m past the
// hysteresis, at the severity uspace-core's judgement gives it
// (warning). The DEM is internal/ground's synthetic tile (at 41.40 N
// 44.60 E: 400 + 10 * 2.4 + 2.4 = 426.4 m). The utm run flew over
// falling ground at constant AMSL; the synthetic tile falls 40 m per
// degree, so this run changes the altitude instead (the judgement is the
// same: AMSL minus the DEM).
func TestScenarioSC04HeightLimitOverTheGround(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-04"})
	s.Seed(seed("sc04.json"))
	ri := standard(t, s)
	const lat, lon, groundM = 41.40, 44.60, 426.4
	rx := s.NewReceiver(s.ReceiverID("rx-sc04"), lat, lon-0.01, ri)

	low, high := ltest.At(lat, lon, groundM+100), ltest.At(lat, lon, groundM+200)
	legs := []ltest.Leg{ltest.Stay(4, low), ltest.Move(3, low, high), ltest.Stay(6, high), ltest.Move(3, high, low), ltest.Stay(8, low)}
	ac := &ltest.Aircraft{Transmitter: mac(0x401), Serial: "TESTSC0400001", OperatorID: "GEOTEST00000401", System: true, Path: ltest.Legs(legs...)}
	f := rx.Fly(ac)
	f.WaitSteps(ltest.Steps(legs...))
	f.Stop()

	s.Await("the height clear", 30e9, func() bool { return s.Cleared(violation.KindHeight120m, ac.TrackID()) != nil })
	rep := s.Verify(ltest.Raise(violation.KindHeight120m, ac.TrackID(), "resolved").WithSeverity(core.SeverityWarning))
	if len(rep.Observed) == 1 {
		row := s.Store().Find(rep.Observed[0].ViolationID)
		if row == nil || row.Peak == nil || math.Abs(*row.Peak-200) > 1 || row.TerrainDataset == nil || *row.TerrainDataset != "COP-DEM GLO-30" {
			t.Errorf("stored height violation %+v: want a peak of 200 m over COP-DEM GLO-30", row)
		}
	}
	s.CheckIdentity(ri, true)
}
