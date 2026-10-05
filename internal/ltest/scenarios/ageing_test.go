package scenarios

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// The ageing and ending paths of a violation, and a receiver's stale
// state (C-05, T-10, E-02). Two aircraft hover in a PROHIBITED zone,
// each heard by its own receiver. A goes silent: its violation clears
// stale once the policy's stale_after_s (15 s) has passed with nothing
// heard, never resolved, and its receiver's status goes live -> stale
// with the silence named; when A is heard again the receiver is live
// and the violation is raised again, then clears resolved as A flies
// out. B lands inside the zone (ODID status ground): its violation
// clears landed.
func TestScenarioStaleLandedAndASilentReceiver(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "ageing"})
	sd := s.Seed(seed("ageing.json"))
	z := s.ZoneByID(sd, "AGE1")
	ri := standard(t, s)
	rxA := s.NewReceiver(s.ReceiverID("rx-age-a"), z.LatDeg, z.LonDeg-0.005, ri)
	rxB := s.NewReceiver(s.ReceiverID("rx-age-b"), z.LatDeg, z.LonDeg+0.005, ri)

	// A: hover until quiet, silent until heard, then hover until it
	// leaves; the phase steps are set by the test as it goes.
	var quietAt, heardAt, leaveAt atomic.Int64
	in, out := centre(z, 520), outside(z, 520)
	a := &ltest.Aircraft{Transmitter: mac(0xA01), Serial: "TESTAGE000001", OperatorID: "GEOTEST00002502", System: true,
		Path: func(step int) ltest.State {
			k := int64(step)
			switch {
			case leaveAt.Load() > 0 && k >= leaveAt.Load():
				return ltest.Legs(ltest.Move(3, in, out), ltest.Stay(1, out))(step - int(leaveAt.Load()))
			case heardAt.Load() > 0 && k >= heardAt.Load():
				return ltest.Hold(in.LatDeg, in.LonDeg, in.AltAMSLM)(step)
			case quietAt.Load() > 0 && k >= quietAt.Load():
				return ltest.State{Silent: true}
			}
			return ltest.Hold(in.LatDeg, in.LonDeg, in.AltAMSLM)(step)
		}}
	bIn := near(z, -0.0005, 0, 520)
	var landAt atomic.Int64
	b := &ltest.Aircraft{Transmitter: mac(0xA02), Serial: "TESTAGE000002", OperatorID: "GEOTEST00002502", System: true,
		Path: func(step int) ltest.State {
			if l := landAt.Load(); l > 0 && int64(step) >= l {
				return ltest.Legs(ltest.Landed(1, ltest.At(bIn.LatDeg, bIn.LonDeg, 430)))(0)
			}
			return ltest.Hold(bIn.LatDeg, bIn.LonDeg, bIn.AltAMSLM)(step)
		}}
	fa, fb := rxA.Fly(a), rxB.Fly(b)
	subjectA := "src.v1.direct_rid." + rxA.ID

	va := s.AwaitRaised(violation.KindZoneIncursion, a.TrackID(), 20*time.Second)
	vb := s.AwaitRaised(violation.KindZoneIncursion, b.TrackID(), 20*time.Second)
	s.AwaitSourceState(subjectA, "live", time.Time{}, 10*time.Second)

	// B lands: landed.
	landAt.Store(int64(fb.Steps() + 1))
	if r := s.AwaitCleared(vb.ID, 10*time.Second); r != "landed" {
		t.Errorf("B cleared %s, want landed", r)
	}

	// A goes quiet: stale after stale_after_s, never resolved.
	quietAt.Store(int64(fa.Steps() + 1))
	silent := time.Now()
	if r := s.AwaitCleared(va.ID, 30*time.Second); r != "stale" {
		t.Errorf("A cleared %s, want stale", r)
	}
	staleAfter := time.Since(silent)
	if staleAfter < 14*time.Second {
		t.Errorf("A cleared stale %v after its last sample, before the policy's 15 s", staleAfter)
	}
	s.Note("silence_to_stale_clear_ms", staleAfter.Milliseconds())
	s.AwaitSourceState(subjectA, "stale", silent, 15*time.Second)

	// A heard again: the receiver is live, the violation raised again.
	heardAt.Store(int64(fa.Steps() + 1))
	back := time.Now()
	s.AwaitSourceState(subjectA, "live", back, 10*time.Second)
	va2 := s.AwaitRaised(violation.KindZoneIncursion, a.TrackID(), 10*time.Second)
	leaveAt.Store(int64(fa.Steps() + 1))
	if r := s.AwaitCleared(va2.ID, 20*time.Second); r != "resolved" {
		t.Errorf("A cleared %s, want resolved", r)
	}
	fa.Stop()
	fb.Stop()

	// unknown until its first batch, then live, stale, live.
	if st := s.Rec.SourceStates(subjectA); !slices.Equal(st, []string{"unknown", "live", "stale", "live"}) &&
		!slices.Equal(st, []string{"live", "stale", "live"}) {
		t.Errorf("receiver A went through %v, want (unknown,) live, stale, live", st)
	}
	s.Verify(
		ltest.Raise(violation.KindZoneIncursion, a.TrackID(), "stale", "resolved").InZone(z.ZoneID()),
		ltest.Raise(violation.KindZoneIncursion, b.TrackID(), "landed").InZone(z.ZoneID()),
	)
	s.CheckIdentity(ri, true)
}
