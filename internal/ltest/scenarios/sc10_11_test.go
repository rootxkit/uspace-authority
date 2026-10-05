package scenarios

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/odid"

	"github.com/rootxkit/uspace-authority/internal/ltest"
)

// SC-11 (receiver latency, S-27, T-07) through rid-ingest: every batch
// is delivered 2 s after it was heard, signed when sent, with no drops.
// Every observation of a transmitter that knows UTC is placed at its
// broadcast time, 1.9 to 2.1 s before its receipt (the field holds
// tenths; the simulator hears each step just after a tenth). The control, a transmitter that does not know UTC yet (R-16:
// no timestamp), is never placed at a broadcast time.
func TestScenarioSC11ReceiverLatency(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-11"})
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)
	const lat, lon = 41.36, 44.62
	rx := s.NewReceiver(s.ReceiverID("rx-sc11"), lat, lon, ri)
	rx.Latency = 2 * time.Second
	timed := &ltest.Aircraft{Transmitter: mac(0xB11), Serial: "TESTSC1100001", Path: ltest.Hold(lat, lon+0.001, 520)}
	untimed := &ltest.Aircraft{Transmitter: mac(0xB12), Serial: "TESTSC1100002", UTCFromStep: 1 << 30, Path: ltest.Hold(lat, lon+0.002, 520)}
	f := rx.Fly(timed, untimed)
	f.WaitSteps(30)
	f.Stop()
	s.Await("the timed transmitter's tracks", 10*time.Second, func() bool { return len(s.Rec.Tracks(timed.TrackID())) >= 29 })

	lo, hi := math.Inf(1), math.Inf(-1)
	for _, o := range s.Rec.Tracks(timed.TrackID()) {
		rxTS, err1 := time.Parse(time.RFC3339Nano, o.Msg.RxTS)
		captured, err2 := time.Parse(time.RFC3339Nano, o.Msg.CapturedAt)
		if err1 != nil || err2 != nil || o.Msg.TimeSource != core.TimeBroadcast {
			t.Fatalf("timed track %+v", o.Msg)
		}
		lag := rxTS.Sub(captured).Seconds()
		lo, hi = math.Min(lo, lag), math.Max(hi, lag)
	}
	if lo < 1.9 || hi > 2.1 {
		t.Errorf("placed %.3f to %.3f s before receipt, want 1.9 to 2.1 s", lo, hi)
	}
	untimedTracks := s.Rec.Tracks(untimed.TrackID())
	if len(untimedTracks) == 0 {
		t.Fatal("no track of the control")
	}
	for _, o := range untimedTracks {
		if o.Msg.TimeSource == core.TimeBroadcast {
			t.Fatalf("a transmitter without a timestamp placed at a broadcast time: %+v", o.Msg)
		}
	}
	s.Note("broadcast_lag_s", map[string]float64{"min": lo, "max": hi})
	s.Note("control_time_source", string(untimedTracks[0].Msg.TimeSource))
	t.Logf("SC-11: %d observations placed at broadcast time %.3f to %.3f s before receipt; the control (no timestamp) placed by %s",
		len(s.Rec.Tracks(timed.TrackID())), lo, hi, untimedTracks[0].Msg.TimeSource)
	s.Verify()
	s.CheckIdentity(ri, true)
}

// SC-10 (a serial change on a reused address with drops, S-32, I-01)
// through rid-ingest: a Bluetooth 4 module (one message per datagram, a
// Basic ID every third second) broadcasts for 30 s, falls silent for
// 4 s, and restarts with a new serial on the same address. 30 % of the
// other datagrams are dropped; at the restart the first Basic ID and
// the first Location are dropped, so two Locations get through before
// the next Basic ID. No Location after the restart is tracked under the
// old serial; the new serial is tracked.
func TestScenarioSC10SerialChangeOnAReusedAddressWithDrops(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-10"})
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)
	const lat, lon = 41.35, 44.62
	const leg, gap = 30, 4
	restart := leg + gap
	rx := s.NewReceiver(s.ReceiverID("rx-sc10"), lat, lon, ri)
	rng := rand.New(rand.NewPCG(10, 25))
	rx.Drop = func(step int, _ *ltest.Aircraft, _ odid.MessageType) bool {
		switch {
		case step == restart:
			return true // the restart's first Basic ID and first Location
		case step > restart && step < restart+3:
			return false // two Locations through before the next Basic ID
		}
		return rng.Float64() < 0.30
	}
	newSerial := "TESTSC1000002"
	base := ltest.Legs(ltest.Move(leg, ltest.At(lat, lon, 520), ltest.At(lat+0.0027, lon, 520)),
		ltest.Quiet(gap, ltest.At(lat+0.0027, lon, 520)), ltest.Move(leg, ltest.At(lat+0.0027, lon, 520), ltest.At(lat, lon, 520)))
	ac := &ltest.Aircraft{Transmitter: mac(0xB10), Serial: "TESTSC1000001", OnePerDatagram: true, BasicIDEvery: 3,
		Path: func(step int) ltest.State {
			st := base(step)
			if step >= restart {
				st.Serial = &newSerial
			}
			return st
		}}
	f := rx.Fly(ac)
	f.WaitSteps(2*leg + gap)
	f.Stop()

	restartAt := time.Time{}
	s.Await("tracks under the new serial", 15*time.Second, func() bool { return len(s.Rec.Tracks(ltest.SerialTrackID(newSerial))) > 0 })
	for _, o := range s.Rec.Tracks(ltest.SerialTrackID(newSerial)) {
		c, _ := time.Parse(time.RFC3339Nano, o.Msg.CapturedAt)
		if restartAt.IsZero() || c.Before(restartAt) {
			restartAt = c
		}
	}
	old := 0
	var lastOld time.Time
	for _, o := range s.Rec.Tracks(ac.TrackID()) {
		c, _ := time.Parse(time.RFC3339Nano, o.Msg.CapturedAt)
		if c.After(lastOld) {
			lastOld = c
		}
		if !c.Before(restartAt.Add(-time.Duration(2) * time.Second)) {
			old++
		}
	}
	// The restart is 4 s after the old serial's last Location; anything
	// of the old serial within 2 s of the new serial's first track is
	// after the restart.
	if old != 0 {
		t.Errorf("%d Locations tracked under the old serial after the restart (last %v, new serial from %v)", old, lastOld, restartAt)
	}
	newRows := len(s.Rec.Tracks(ltest.SerialTrackID(newSerial)))
	s.Note("sc10", map[string]any{"old_after_restart": old, "new_serial_tracks": newRows, "old_serial_tracks": len(s.Rec.Tracks(ac.TrackID()))})
	t.Logf("SC-10: %d tracks under the old serial, none after the restart; %d under the new", len(s.Rec.Tracks(ac.TrackID())), newRows)
	s.Verify()
	s.CheckIdentity(ri, true)
}
