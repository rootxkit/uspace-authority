package scenarios

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
)

// The Display Provider with nothing to poll (WP-14): a console views an
// area where no ISA exists (no USSP flight active, the staging droplet's
// state). dp-poller searches the DSS for every tile of the viewport and
// says on dp.v1.status that the DSS answered and it holds no provider,
// which picture-ws shows as dp_state idle, not dp_unavailable. The DSS
// down, it says dss_unavailable (so picture-ws says dp_unavailable);
// back, answered again. An ISA appearing is polled at once.
func TestScenarioDPIdleWithoutISAsInView(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "DP-idle"})
	dss, sp := fakedss.NewDSS(), fakedss.NewSP()
	t.Cleanup(dss.Close)
	t.Cleanup(sp.Close)
	tok := ltest.NewTokenServer(t, "authority-01")
	dpp := s.StartDPPoller(dss, tok, nil)

	var mu sync.Mutex
	var last dpviews.Status
	var heard int
	sub, err := s.BP.NC.Subscribe(dpviews.StatusSubject, func(m *nats.Msg) {
		var env bus.Envelope[dpviews.Status]
		if json.Unmarshal(m.Data, &env) != nil || env.Schema != dpviews.StatusSchema {
			t.Errorf("dp.v1.status is not dp/status/v1: %s", m.Data)
			return
		}
		mu.Lock()
		last, heard = env.Body, heard+1
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	state := func() (dpviews.Status, int) { mu.Lock(); defer mu.Unlock(); return last, heard }

	// Nothing viewed: dp-poller speaks, but has not searched.
	s.Await("dp.v1.status heard", 15*time.Second, func() bool { _, n := state(); return n > 0 })
	if b, _ := state(); b.DSS != dpviews.DSSUnknown || b.Tiles != 0 {
		t.Errorf("nothing viewed: %+v, want dss unknown and no tile", b)
	}

	// A console views an area without an ISA: searched, answered, idle.
	box := dp.Box{MinLat: 41.70, MinLon: 44.80, MaxLat: 41.71, MaxLon: 44.81}
	s.PutConsoleView(dpp, "picture-ws dp-idle", dpviews.BBox{box.MinLon, box.MinLat, box.MaxLon, box.MaxLat})
	s.Await("the DSS answered for the viewport, no provider", 30*time.Second, func() bool {
		b, _ := state()
		return b.DSS == dpviews.DSSAnswered && b.Tiles > 0 && b.ISAs == 0 && b.Providers == 0
	})
	if n, _, _ := dss.Counts(); n == 0 {
		t.Error("idle without an ISA search")
	}
	if polls, _ := sp.Counts(); polls != 0 {
		t.Errorf("the Service Provider was polled %d times with no ISA", polls)
	}

	// The DSS down: not idle.
	dss.SetDown(true)
	s.Await("dss_unavailable said", 60*time.Second, func() bool { b, _ := state(); return b.DSS == dpviews.DSSUnavailable && b.DSSSince != nil })
	dss.SetDown(false)
	s.Await("the DSS answering again", 60*time.Second, func() bool { b, _ := state(); return b.DSS == dpviews.DSSAnswered })

	// An ISA appears: its provider is held and polled, no longer idle.
	now := time.Now()
	dss.PutISA("isa-dp-idle", "ussp-LAB-01", ltest.HostURL(sp.URL()), box, now.Add(-time.Minute), now.Add(time.Hour))
	s.Await("the ISA's provider held", 60*time.Second, func() bool { b, _ := state(); return b.Providers > 0 })
}
