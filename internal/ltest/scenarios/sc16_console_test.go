package scenarios

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
	"github.com/rootxkit/uspace-authority/internal/track"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// SC-16 through a console's viewport (WP-14): no oversight area is
// published, so dp-poller polls only what a console views. With no
// viewport nothing is polled; once picture-ws's report of a console
// viewport over the zone is in the views bucket, the certified USSP's
// Service Provider is polled, its status goes live, flight A (known only
// to the network) is raised in the PROHIBITED zone and resolved when it
// flies out. dp-poller refused every complete listing of that bucket
// (nats: invalid subscription), so on the droplet no console viewport
// was ever polled and the picture said dp_unavailable; SC-16 publishes
// oversight areas and never ran this path.
func TestScenarioSC16ConsoleViewportPolled(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "SC-16-console"})
	sd := s.Seed(seed("sc16.json"))
	z := s.ZoneByID(sd, "SC16")
	const uss = "ussp-LAB-01"

	dss, sp := fakedss.NewDSS(), fakedss.NewSP()
	t.Cleanup(dss.Close)
	t.Cleanup(sp.Close)
	tok := ltest.NewTokenServer(t, "authority-01")
	standard(t, s)
	dpp := s.StartDPPoller(dss, tok, nil)
	s.PutCertified(dpp, 1, certkv.USSP{ClientID: uss, Code: "LAB", BaseURL: "https://lab.example.test", Status: "operating"})
	box := dp.Box{MinLat: z.LatDeg - 0.005, MinLon: z.LonDeg - 0.006, MaxLat: z.LatDeg + 0.005, MaxLon: z.LonDeg + 0.006}
	now := time.Now()
	dss.PutISA("isa-sc16c", uss, ltest.HostURL(sp.URL()), box, now.Add(-time.Minute), now.Add(time.Hour))

	const n = 15.9 // the test geoid
	var leaving atomic.Bool
	a := ltest.SPFlight{ID: "fl-sc16c-a", Serial: "TEST9SC1600001", OperatorID: "GEOTEST00001601", At: func(time.Time) (float64, float64, float64) {
		if leaving.Load() {
			return z.LatDeg + 0.003, z.LonDeg, 520 + n
		}
		return z.LatDeg, z.LonDeg, 520 + n
	}}
	s.ServeFlights(sp, a)
	idA := ltest.SerialTrackID(a.Serial)
	network := func() int {
		k := 0
		for _, o := range s.Rec.Tracks(idA) {
			if o.Msg.Body.Source == track.SourceNetworkRID {
				k++
			}
		}
		return k
	}

	// No viewport and no oversight area: nothing is polled.
	time.Sleep(5 * time.Second)
	if polls, _ := sp.Counts(); polls != 0 {
		t.Errorf("the Service Provider was polled %d times with nothing viewed", polls)
	}
	if k := network(); k != 0 {
		t.Errorf("%d network tracks of A with nothing viewed", k)
	}

	// A console views the zone: polled, live, A raised.
	viewed := time.Now()
	s.PutConsoleView(dpp, "picture-ws sc16c", dpviews.BBox{box.MinLon, box.MinLat, box.MaxLon, box.MaxLat})
	s.Await("the Service Provider polled for the console's viewport", 30*time.Second, func() bool { k, _ := sp.Counts(); return k > 0 })
	s.Note("view_to_poll_ms", time.Since(viewed).Milliseconds())
	s.AwaitSourceState(ltest.NetworkSubject(uss), dp.StateLive, viewed, 30*time.Second)
	s.Await("network tracks of A", 30*time.Second, func() bool { return network() >= 3 })
	va := s.AwaitRaised(violation.KindZoneIncursion, idA, 15*time.Second)

	// A flies out: resolved.
	leaving.Store(true)
	if r := s.AwaitCleared(va.ID, 20*time.Second); r != "resolved" {
		t.Errorf("A cleared %s after leaving, want resolved", r)
	}
	s.Verify(ltest.Raise(violation.KindZoneIncursion, idA, "resolved").InZone(z.ZoneID()))
}
