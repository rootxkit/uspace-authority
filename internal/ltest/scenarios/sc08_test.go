package scenarios

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-08 (switching sources off and on, B-09, B-11) for direct Remote
// ID, through api's switch service: two receivers each hear one
// aircraft hovering in its own PROHIBITED zone. Receiver A switched off
// clears only A's violation, as source_disabled, at once, and A's
// batches are refused 503 source_disabled; switched on, A is raised
// again. Remote ID switched off by type clears both; on, both are
// raised again; flying out clears both resolved. Every switch is an
// events row with the actor and the reason.
func TestScenarioSC08SourcesSwitchedOffAndOn(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-08"})
	sd := s.Seed(seed("sc08.json"))
	za, zb := s.ZoneByID(sd, "SC8A"), s.ZoneByID(sd, "SC8B")
	ri := standard(t, s)
	rxA := s.NewReceiver(s.ReceiverID("rx-sc08a"), za.LatDeg, za.LonDeg-0.005, ri)
	rxB := s.NewReceiver(s.ReceiverID("rx-sc08b"), zb.LatDeg, zb.LonDeg+0.005, ri)

	var leaving atomic.Int64 // the step at which both start to leave (0: hover)
	path := func(z ltest.Zone) ltest.Path {
		in, out := centre(z, 520), outside(z, 520)
		return func(step int) ltest.State {
			l := leaving.Load()
			if l == 0 || int64(step) < l {
				return ltest.Legs(ltest.Stay(1, in))(0)
			}
			return ltest.Legs(ltest.Move(3, in, out), ltest.Stay(1, out))(step - int(l))
		}
	}
	a := &ltest.Aircraft{Transmitter: mac(0x801), Serial: "TESTSC0800001", OperatorID: "GEOTEST00000801", System: true, Path: path(za)}
	b := &ltest.Aircraft{Transmitter: mac(0x802), Serial: "TESTSC0800002", OperatorID: "GEOTEST00000801", System: true, Path: path(zb)}
	fa, fb := rxA.Fly(a), rxB.Fly(b)

	s.AwaitRaised(violation.KindZoneIncursion, a.TrackID(), 20*time.Second)
	vb := s.AwaitRaised(violation.KindZoneIncursion, b.TrackID(), 20*time.Second)

	// Receiver A off: only A clears, source_disabled, and A is refused.
	va := s.Open(violation.KindZoneIncursion, a.TrackID())
	instA := rxA.ID
	off := time.Now()
	s.Switch(sources.TypeDirectRID, &instA, false, "SC-08 step 4: one receiver off")
	if r := s.AwaitCleared(va.ID, 5*time.Second); r != "source_disabled" {
		t.Errorf("A cleared %s, want source_disabled", r)
	}
	s.Note("instance_off_to_clear_ms", time.Since(off).Milliseconds())
	// The console's view of it: receiver A disabled, by instance.
	s.AwaitSourceState("src.v1.direct_rid."+instA, "disabled", off, 10*time.Second)
	fa.WaitSteps(3)
	if s.Open(violation.KindZoneIncursion, b.TrackID()) == nil {
		t.Error("B's violation cleared when only receiver A was switched off")
	}
	if n := rxA.Tally().RefusedBy["503 source_disabled"]; n == 0 {
		t.Errorf("receiver A switched off was not refused 503 source_disabled: %+v", rxA.Tally())
	}

	// Receiver A on: raised again within a second or two.
	on := time.Now()
	s.Switch(sources.TypeDirectRID, &instA, true, "SC-08 step 5: the receiver back")
	va2 := s.AwaitRaised(violation.KindZoneIncursion, a.TrackID(), 10*time.Second)
	s.Note("instance_on_to_raise_ms", va2.RaisedAt.Sub(on).Milliseconds())

	// Remote ID off by type: both clear source_disabled.
	s.Switch(sources.TypeDirectRID, nil, false, "SC-08 step 2: Remote ID off by type")
	for _, id := range []string{va2.ID, vb.ID} {
		if r := s.AwaitCleared(id, 5*time.Second); r != "source_disabled" {
			t.Errorf("%s cleared %s, want source_disabled", id, r)
		}
	}
	fa.WaitSteps(3)
	s.Switch(sources.TypeDirectRID, nil, true, "SC-08 step 3: Remote ID on")
	va3 := s.AwaitRaised(violation.KindZoneIncursion, a.TrackID(), 10*time.Second)
	vb3 := s.AwaitRaised(violation.KindZoneIncursion, b.TrackID(), 10*time.Second)

	// Out of the zones: both clear resolved.
	leaving.Store(int64(max(fa.Steps(), fb.Steps()) + 1))
	for _, id := range []string{va3.ID, vb3.ID} {
		if r := s.AwaitCleared(id, 20*time.Second); r != "resolved" {
			t.Errorf("%s cleared %s, want resolved", id, r)
		}
	}
	fa.Stop()
	fb.Stop()

	s.Verify(
		ltest.Raise(violation.KindZoneIncursion, a.TrackID(), "source_disabled", "source_disabled", "resolved").InZone(za.ZoneID()),
		ltest.Raise(violation.KindZoneIncursion, b.TrackID(), "source_disabled", "resolved").InZone(zb.ZoneID()),
	)
	if ev := s.EventTypes("source", sources.TypeDirectRID+"/"+instA); !slices.Equal(ev, []string{"source_disabled", "source_enabled"}) {
		t.Errorf("receiver A's switch events %v", ev)
	}
	if ev := s.EventTypes("source", sources.TypeDirectRID+"/*"); !slices.Equal(ev, []string{"source_disabled", "source_enabled"}) {
		t.Errorf("Remote ID's switch events %v", ev)
	}
	s.CheckIdentity(ri, true)
}
