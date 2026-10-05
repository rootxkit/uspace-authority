package scenarios

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-16 (a network Remote ID provider switched off, B-11) and the
// network Remote ID alert path with its degraded state (R-14, E-02):
// dp-poller discovers a certified USSP's ISA through the fake DSS and
// polls its fake Service Provider. Flight A, known only to the network,
// hovers in a PROHIBITED zone: zone_incursion with evidence trust
// provider. SYSID 2 is served by the Service Provider and heard by
// direct Remote ID outside the zone. The provider switched off: polling
// stops at once, A's violation clears source_disabled, the status says
// disabled, and SYSID 2 stays on the picture through direct Remote ID;
// on again, polling resumes and A is raised again. The Service Provider
// taken down: its status goes down (degraded, never removed) and A's
// violation ages out stale while SYSID 2's direct track continues; back
// up, the status is live and A is raised again; A flies out: resolved.
// The serials are ANSI/CTA-2063-A ("TEST", length code 9, nine
// characters): a Display Provider takes a flight's serial only when it
// is one, and only then gives it the serial's track id.
func TestScenarioSC16NetworkProviderOffOnAndDown(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-16"})
	sd := s.Seed(seed("sc16.json"))
	z := s.ZoneByID(sd, "SC16")
	const uss = "ussp-LAB-01"

	dss, sp := fakedss.NewDSS(), fakedss.NewSP()
	t.Cleanup(dss.Close)
	t.Cleanup(sp.Close)
	tok := ltest.NewTokenServer(t, "authority-01")
	ri := standard(t, s)
	dpp := s.StartDPPoller(dss, tok, nil)
	s.PutCertified(dpp, 1, certkv.USSP{ClientID: uss, Code: "LAB", BaseURL: "https://lab.example.test", Status: "operating"})
	box := dp.Box{MinLat: z.LatDeg - 0.005, MinLon: z.LonDeg - 0.006, MaxLat: z.LatDeg + 0.005, MaxLon: z.LonDeg + 0.006}
	s.PutOversight(dpp, 1, dpviews.Area{ID: 1, Label: "SC-16", BBox: dpviews.BBox{box.MinLon, box.MinLat, box.MaxLon, box.MaxLat}})
	now := time.Now()
	dss.PutISA("isa-sc16", uss, ltest.HostURL(sp.URL()), box, now.Add(-time.Minute), now.Add(time.Hour))

	const n = 15.9 // the test geoid
	var leaving atomic.Bool
	a := ltest.SPFlight{ID: "fl-sc16-a", Serial: "TEST9SC1600001", OperatorID: "GEOTEST00001601", At: func(time.Time) (float64, float64, float64) {
		if leaving.Load() {
			return z.LatDeg + 0.003, z.LonDeg, 520 + n
		}
		return z.LatDeg, z.LonDeg, 520 + n
	}}
	two := ltest.At(z.LatDeg-0.003, z.LonDeg, 520)
	sys2 := ltest.SPFlight{ID: "fl-sc16-2", Serial: "TEST9SC1600002", OperatorID: "GEOTEST00001601", At: func(time.Time) (float64, float64, float64) {
		return two.LatDeg, two.LonDeg, two.AltAMSLM + n
	}}
	s.ServeFlights(sp, a, sys2)
	rx := s.NewReceiver(s.ReceiverID("rx-sc16"), z.LatDeg, z.LonDeg-0.01, ri)
	direct := &ltest.Aircraft{Transmitter: mac(0x1602), Serial: "TEST9SC1600002", OperatorID: "GEOTEST00001601", System: true,
		Path: ltest.Hold(two.LatDeg, two.LonDeg, two.AltAMSLM)}
	f := rx.Fly(direct)
	idA := ltest.SerialTrackID(a.Serial)
	network := func(id string, after time.Time) int {
		k := 0
		for _, o := range s.Rec.Tracks(id) {
			if o.Msg.Body.Source == track.SourceNetworkRID && o.At.After(after) {
				k++
			}
		}
		return k
	}
	directSince := func(id string, after time.Time) int {
		k := 0
		for _, o := range s.Rec.Tracks(id) {
			if o.Msg.Body.Source == track.SourceDirectRID && o.At.After(after) {
				k++
			}
		}
		return k
	}

	s.Await("network tracks of A", 30*time.Second, func() bool { return network(idA, time.Time{}) >= 3 })
	va := s.AwaitRaised(violation.KindZoneIncursion, idA, 15*time.Second)
	for _, al := range s.Rec.Alerts() {
		if al.Msg.Body.ViolationID == va.ID && al.Msg.Body.EvidenceTrust != core.TrustProvider {
			t.Errorf("A's violation evidence trust %s, want provider", al.Msg.Body.EvidenceTrust)
		}
	}

	// Switched off: polling stops, A clears source_disabled, SYSID 2
	// stays through direct Remote ID.
	inst := uss
	s.Switch(sources.TypeNetworkRID, &inst, false, "SC-16 step 2")
	off := time.Now()
	if r := s.AwaitCleared(va.ID, 10*time.Second); r != "source_disabled" {
		t.Errorf("A cleared %s, want source_disabled", r)
	}
	s.AwaitSourceState(ltest.NetworkSubject(uss), dp.StateDisabled, off, 10*time.Second)
	f.WaitSteps(2)
	polls, _ := sp.Counts()
	quiet := time.Now()
	f.WaitSteps(4)
	if again, _ := sp.Counts(); again != polls {
		t.Errorf("the Service Provider was polled %d more times while switched off", again-polls)
	}
	if k := network(idA, quiet); k != 0 {
		t.Errorf("%d network tracks of A published while the provider was off", k)
	}
	if k := directSince(ltest.SerialTrackID(sys2.Serial), quiet); k < 3 {
		t.Errorf("SYSID 2 left the picture with the provider off: %d direct tracks", k)
	}

	// On again: polling resumes within a second or two, A raised again.
	on := time.Now()
	s.Switch(sources.TypeNetworkRID, &inst, true, "SC-16 step 3")
	s.Await("polling resumed", 10*time.Second, func() bool { k, _ := sp.Counts(); return k > polls })
	s.Note("on_to_poll_ms", time.Since(on).Milliseconds())
	va2 := s.AwaitRaised(violation.KindZoneIncursion, idA, 15*time.Second)

	// The Service Provider down: its status goes down, A ages out stale,
	// SYSID 2's direct track continues.
	sp.SetDown(true)
	down := time.Now()
	s.AwaitSourceState(ltest.NetworkSubject(uss), dp.StateDown, down, 30*time.Second)
	if r := s.AwaitCleared(va2.ID, 30*time.Second); r != "stale" {
		t.Errorf("A cleared %s with its provider down, want stale", r)
	}
	if k := directSince(ltest.SerialTrackID(sys2.Serial), down); k < 10 {
		t.Errorf("SYSID 2 has %d direct tracks while the provider was down", k)
	}
	sp.SetDown(false)
	up := time.Now()
	s.AwaitSourceState(ltest.NetworkSubject(uss), dp.StateLive, up, 30*time.Second)
	va3 := s.AwaitRaised(violation.KindZoneIncursion, idA, 15*time.Second)

	leaving.Store(true)
	if r := s.AwaitCleared(va3.ID, 20*time.Second); r != "resolved" {
		t.Errorf("A cleared %s after leaving, want resolved", r)
	}
	f.Stop()
	s.Note("provider_states", s.Rec.SourceStates(ltest.NetworkSubject(uss)))
	s.Verify(ltest.Raise(violation.KindZoneIncursion, idA, "source_disabled", "stale", "resolved").InZone(z.ZoneID()))
	s.CheckIdentity(ri, true)
}
