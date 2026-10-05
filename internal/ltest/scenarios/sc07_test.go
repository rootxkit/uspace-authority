package scenarios

import (
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// pass is one pass through z and back out: hover outside, fly in, hover
// inside, fly out, and hover outside long enough for the clear
// hysteresis (3 s) to run at 1 Hz.
func pass(z ltest.Zone, altAMSLM float64) []ltest.Leg {
	out, in := outside(z, altAMSLM), centre(z, altAMSLM)
	return []ltest.Leg{ltest.Stay(3, out), ltest.Move(3, out, in), ltest.Stay(6, in), ltest.Move(3, in, out), ltest.Stay(8, out)}
}

// SC-07: one aircraft carrying a registered transmitter and an
// unidentified one (no Basic ID) flies through a PROHIBITED zone and
// back, twice. On each pass the registered track raises only its zone
// violation; the unidentified one raises its zone violation and a
// critical unregistered; all clear resolved on exit. Every transition
// is stored with its events row (INV-02).
func TestScenarioSC07UnidentifiedAircraftThroughAProhibitedZone(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-07"})
	sd := s.Seed(seed("sc07.json"))
	z := s.ZoneByID(sd, "SC7")
	ri := standard(t, s)
	rx := s.NewReceiver(s.ReceiverID("rx-sc07"), z.LatDeg, z.LonDeg-0.01, ri)

	legs := append(pass(z, 520), pass(z, 520)...)
	reg := &ltest.Aircraft{Transmitter: mac(0x701), Serial: "TESTSC0700001", OperatorID: "GEOTEST00000701", System: true, Path: ltest.Legs(legs...)}
	uni := &ltest.Aircraft{Transmitter: mac(0x702), Path: ltest.Legs(legs...)}
	f := rx.Fly(reg, uni)
	f.WaitSteps(ltest.Steps(legs...))
	f.Stop()

	s.Await("both passes cleared", 30e9, func() bool {
		n := 0
		for _, v := range s.Rec.Violations() {
			if !v.ClearedAt.IsZero() {
				n++
			}
		}
		return n >= 6
	})
	s.Verify(
		ltest.Raise(violation.KindZoneIncursion, reg.TrackID(), "resolved", "resolved").InZone(z.ZoneID()).WithSeverity(core.SeverityCritical),
		ltest.Raise(violation.KindZoneIncursion, uni.TrackID(), "resolved", "resolved").InZone(z.ZoneID()).WithSeverity(core.SeverityCritical),
		ltest.Raise(violation.KindUnregistered, uni.TrackID(), "resolved", "resolved").WithSeverity(core.SeverityCritical),
	)
	s.CheckIdentity(ri, true)
}
