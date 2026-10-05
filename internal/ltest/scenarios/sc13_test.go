package scenarios

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-13 (an AGL zone with no DEM, Z-09, SC-22): detect runs without
// terrain. It says, at error level at start and on every status line,
// that it cannot judge everything. A PROHIBITED and a REQ_AUTHORIZATION
// zone of 0-120 m AGL each raise a warning (not critical) with
// vertical_known false, limit_not_judged true and not_judged [AGL],
// cleared resolved on exit; a CONDITIONAL zone of 0-120 m AGL raises
// nothing. No height_120m either: without a DEM the height limit is not
// evaluated.
func TestScenarioSC13AGLZonesWithNoDEM(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-13"})
	sd := s.Seed(seed("sc13.json"))
	zp, zr, zc := s.ZoneByID(sd, "SC13P"), s.ZoneByID(sd, "SC13R"), s.ZoneByID(sd, "SC13C")
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)
	det := s.StartDetect(map[string]string{"GROUND_DIR": ""})
	s.StartViolationStore()
	if l := det.WaitLine("violations not judged in full", nil, 20*time.Second); l["level"] != "ERROR" {
		t.Errorf("the start says %v, want ERROR naming what is not judged", l)
	}
	det.WaitLine("status", func(m map[string]any) bool { return m["level"] == "ERROR" }, 10*time.Second)

	rx := s.NewReceiver(s.ReceiverID("rx-sc13"), zp.LatDeg, zp.LonDeg-0.01, ri)
	serials := []string{"TESTSC1300001", "TESTSC1300002", "TESTSC1300003"}
	acs := make([]*ltest.Aircraft, 0, 3)
	for i, z := range []ltest.Zone{zp, zr, zc} {
		acs = append(acs, &ltest.Aircraft{Transmitter: mac(0xD01 + i), Serial: serials[i], OperatorID: "GEOTEST00001301", System: true,
			Path: ltest.Legs(pass(z, 520)...)})
	}
	f := rx.Fly(acs...)
	f.WaitSteps(ltest.Steps(pass(zp, 520)...))
	f.Stop()
	s.Await("the two warnings cleared", 20*time.Second, func() bool {
		return s.Cleared(violation.KindZoneIncursion, acs[0].TrackID()) != nil && s.Cleared(violation.KindZoneIncursion, acs[1].TrackID()) != nil
	})
	for _, a := range s.Rec.Alerts() {
		b := a.Msg.Body
		if b.State != violation.StateRaised {
			continue
		}
		nj, _ := b.Detail["not_judged"].([]any)
		if b.Detail["vertical_known"] != false || b.Detail["limit_not_judged"] != true || len(nj) != 1 || nj[0] != "AGL" {
			t.Errorf("%s %s detail %v: want vertical_known false, limit_not_judged true, not_judged [AGL]", b.ViolationID, b.Kind, b.Detail)
		}
	}
	s.Verify(
		ltest.Raise(violation.KindZoneIncursion, acs[0].TrackID(), "resolved").InZone(zp.ZoneID()).WithSeverity(core.SeverityWarning),
		ltest.Raise(violation.KindZoneIncursion, acs[1].TrackID(), "resolved").InZone(zr.ZoneID()).WithSeverity(core.SeverityWarning),
	)
	s.Note("monitor_counters", det.Counters())
	s.CheckIdentity(ri, true)
}
