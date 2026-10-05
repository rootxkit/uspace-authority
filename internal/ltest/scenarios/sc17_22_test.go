package scenarios

import (
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/ltest"
)

// SC-17 step 2 (a registry change reaches the resolver, G-08), timed:
// a registered aircraft is broadcasting and resolves registered; its
// aircraft is suspended in the registry projection (api's projector
// write, then registry.v1.changed after the commit). rid-ingest's next
// tracks say suspended within the reader refresh (RID_PROJECTION_REFRESH_S,
// 5 s) plus the transaction. Steps 3 to 6 (a failed projection write,
// the periodic repair, a change during a repair, an unreadable
// projection) are api's and the reader's, tested in internal/registry.
func TestScenarioSC17ASuspensionReachesTheResolver(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-17"})
	ops := []ltest.Operator{{ID: "op-sc17-1", RegistrationNumber: "GEOTEST00001701", Status: "active"}}
	uas := ltest.UAS{ID: "uas-sc17-1", Serial: "TESTSC1700001", Status: "active", OperatorID: "op-sc17-1"}
	s.SeedRegistry(ops, []ltest.UAS{uas})
	ri := s.StartRIDIngest(nil)
	s.StartTSDBWriter(nil)
	const lat, lon = 41.32, 44.62
	rx := s.NewReceiver(s.ReceiverID("rx-sc17"), lat, lon, ri)
	ac := &ltest.Aircraft{Transmitter: mac(0x171), Serial: uas.Serial, OperatorID: "GEOTEST00001701", System: true, Path: ltest.Hold(lat, lon+0.001, 520)}
	f := rx.Fly(ac)
	status := func(after time.Time) core.IdentStatus {
		var last core.IdentStatus
		for _, o := range s.Rec.Tracks(ac.TrackID()) {
			if o.At.After(after) {
				last = o.Msg.Body.Identification.Status
			}
		}
		return last
	}
	s.Await("registered", 15*time.Second, func() bool { return status(time.Time{}) == core.IdentRegistered })

	uas.Status = "suspended"
	changed := time.Now()
	s.SeedRegistry(ops, []ltest.UAS{uas})
	s.Await("suspended", 10*time.Second, func() bool { return status(changed) == core.IdentSuspended })
	took := time.Since(changed)
	f.WaitSteps(2)
	f.Stop()
	if took > 6*time.Second {
		t.Errorf("the suspension reached the tracks %v after the commit, past the 5 s refresh", took)
	}
	s.Note("change_to_suspended_track_ms", took.Milliseconds())
	t.Logf("SC-17: suspended on the tracks %v after the projection commit", took)
	s.Verify()
	s.CheckIdentity(ri, true)
}

// SC-22 (a data source that does not exist yet must not be silence,
// E-02, D-04, Z-09), as a design check through the processes: rid-ingest
// with no geoid and no registry projection, detect with no terrain, no
// geoid and no projections, and no switch state published. The aircraft
// are on the picture with no AMSL altitude and identification
// registry_unavailable (no_serial for the one without a serial); every
// status line says the geoid is not loaded, the projection not loaded
// and the switch state unknown; detect's status is at error level, and
// nothing is raised from what cannot be judged.
func TestScenarioSC22MissingSourcesAreSaidNotSilent(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-22", NoPolicy: true})
	unreachable := "postgres://unused@127.0.0.1:1/unused"
	ri := s.StartRIDIngest(map[string]string{"GEOID_FILE": "", "TS_URL": unreachable})
	det := s.StartDetect(map[string]string{"GROUND_DIR": "", "GEOID_FILE": "", "TS_URL": unreachable})
	s.StartViolationStore()
	const lat, lon = 41.31, 44.62
	rx := s.NewReceiver(s.ReceiverID("rx-sc22"), lat, lon, ri)
	serial := &ltest.Aircraft{Transmitter: mac(0x221), Serial: "TESTSC2200001", OperatorID: "GEOTEST00002201", Path: ltest.Hold(lat, lon+0.001, 520)}
	bare := &ltest.Aircraft{Transmitter: mac(0x222), Path: ltest.Hold(lat, lon+0.002, 520)}
	f := rx.Fly(serial, bare)
	s.Await("both on the picture", 20*time.Second, func() bool {
		return len(s.Rec.Tracks(serial.TrackID())) > 0 && len(s.Rec.Tracks(bare.TrackID())) > 0
	})
	f.WaitSteps(3)
	f.Stop()
	for id, reason := range map[string]core.IdentReason{serial.TrackID(): core.ReasonRegistryUnavailable, bare.TrackID(): core.ReasonNoSerial} {
		for _, o := range s.Rec.Tracks(id) {
			b := o.Msg.Body
			if b.AltAMSLM != nil || b.AltSource != core.AltNone || b.Identification.Reason != reason {
				t.Errorf("track %s: AMSL %v source %s reason %s, want none, none, %s", id, b.AltAMSLM, b.AltSource, b.Identification.Reason, reason)
				break
			}
		}
	}
	for _, p := range []*ltest.Proc{ri.Proc, det.Proc} {
		l := p.WaitLine("status", func(m map[string]any) bool {
			return m["projection_loaded"] == false || m["zones_projection_loaded"] == false
		}, 10*time.Second)
		if l["source_control_known"] != false {
			t.Errorf("%s status says the switch state is known: %v", p.Name, l["source_control_known"])
		}
		if g, _ := l["geoid"].(string); g == "loaded" {
			t.Errorf("%s status says a geoid is loaded", p.Name)
		}
		s.Note(p.Name+"_status", l)
	}
	det.WaitLine("status", func(m map[string]any) bool { return m["level"] == "ERROR" }, 10*time.Second)
	det.WaitLine("violations not judged in full", nil, 10*time.Second)
	s.Verify()
	s.CheckIdentity(ri, false)
}
