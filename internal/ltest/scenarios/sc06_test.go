package scenarios

import (
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-06 (four identification statuses at once, G-02) and the
// identification_mismatch alert path: four transmitters against one
// registry. SYSID 1 is registered/matched, SYSID 2 suspended/
// uas_suspended, SYSID 3 broadcasts another operator's number
// (unknown_operator/operator_mismatch, mismatch true) and raises
// identification_mismatch, and a transmitter without a Basic ID is
// unidentified/no_serial. SYSID 3 then broadcasts its registered
// operator's number and the mismatch clears resolved. No zone is in
// force, so nothing else may be raised.
func TestScenarioSC06IdentificationStatusesAndMismatch(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-06"})
	s.Seed(seed("sc06.json"))
	ri := standard(t, s)
	const lat, lon = 41.42, 44.62
	rx := s.NewReceiver(s.ReceiverID("rx-sc06"), lat, lon-0.01, ri)

	const fixSteps = 12
	right := "GEOTEST00000601"
	hold := func(dLat float64) ltest.Path { return ltest.Hold(lat+dLat, lon, 520) }
	reg := &ltest.Aircraft{Transmitter: mac(0x601), Serial: "TESTSC0600001", OperatorID: right, System: true, Path: hold(0)}
	sus := &ltest.Aircraft{Transmitter: mac(0x602), Serial: "TESTSC0600002", OperatorID: right, System: true, Path: hold(0.001)}
	wrong := hold(0.002)
	unk := &ltest.Aircraft{Transmitter: mac(0x603), Serial: "TESTSC0600003", OperatorID: "GEOTEST00000699", System: true,
		Path: func(step int) ltest.State {
			st := wrong(step)
			if step >= fixSteps {
				st.OperatorID = &right
			}
			return st
		}}
	uni := &ltest.Aircraft{Transmitter: mac(0x604), Path: hold(0.003)}
	f := rx.Fly(reg, sus, unk, uni)
	f.WaitSteps(fixSteps + 8)
	f.Stop()

	s.Await("the mismatch clear", 20e9, func() bool { return s.Cleared(violation.KindIdentificationMismatch, unk.TrackID()) != nil })
	want := map[string][3]string{
		reg.TrackID(): {"registered", "matched", "false"},
		sus.TrackID(): {"suspended", "uas_suspended", "false"},
		uni.TrackID(): {"unidentified", "no_serial", "false"},
	}
	for id, w := range want {
		tracks := s.Rec.Tracks(id)
		if len(tracks) == 0 {
			t.Errorf("no track %s", id)
			continue
		}
		for _, o := range tracks {
			idn := o.Msg.Body.Identification
			if string(idn.Status) != w[0] || string(idn.Reason) != w[1] || (idn.Mismatch && w[2] == "false") {
				t.Errorf("track %s: %s/%s mismatch %v, want %v", id, idn.Status, idn.Reason, idn.Mismatch, w)
				break
			}
		}
	}
	sawMismatch := false
	for _, o := range s.Rec.Tracks(unk.TrackID()) {
		idn := o.Msg.Body.Identification
		if idn.Mismatch && idn.Status == core.IdentUnknownOperator && idn.Reason == core.ReasonOperatorMismatch &&
			idn.RegisteredOperatorReg != nil && *idn.RegisteredOperatorReg == right {
			sawMismatch = true
		}
	}
	if !sawMismatch {
		t.Error("SYSID 3 never tracked as unknown_operator/operator_mismatch naming its registered operator")
	}
	s.Verify(ltest.Raise(violation.KindIdentificationMismatch, unk.TrackID(), "resolved").WithSeverity(core.SeverityWarning))
	s.CheckIdentity(ri, true)
}
