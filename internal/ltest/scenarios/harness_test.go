package scenarios

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/ltest"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// captureTB is the test's TB with Error and Errorf kept instead of
// failing the test: the runner's own verdicts, read back.
type captureTB struct {
	testing.TB
	mu   sync.Mutex
	errs []string
}

// newCaptureTB is a captureTB over t that fails t, when the test ends,
// with every error no take() read: one kept after the last take() (a
// verdict of Verify, CheckIdentity or the stack's own cleanups) is a
// failure, never swallowed. Registered before anything else on c, the
// check runs after every other cleanup.
func newCaptureTB(t testing.TB) *captureTB {
	c := &captureTB{TB: t}
	t.Cleanup(func() {
		if left := c.take(); left != "" {
			t.Errorf("errors kept after the last take():\n%s", left)
		}
	})
	return c
}

func (c *captureTB) Error(args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, fmt.Sprint(args...))
}

func (c *captureTB) Errorf(format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, fmt.Sprintf(format, args...))
}

func (c *captureTB) take() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := strings.Join(c.errs, "\n")
	c.errs = nil
	return out
}

// recordTB is a TB that records its cleanups and errors instead of
// running and failing: captureTB's own check, read back.
type recordTB struct {
	testing.TB
	cleanups []func()
	errs     []string
}

func (r *recordTB) Helper()           {}
func (r *recordTB) Cleanup(f func())  { r.cleanups = append(r.cleanups, f) }
func (r *recordTB) Error(args ...any) { r.errs = append(r.errs, fmt.Sprint(args...)) }
func (r *recordTB) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func (r *recordTB) runCleanups() {
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		r.cleanups[i]()
	}
}

// An error kept after the last take() fails the test when it ends; one
// read by take(), or none at all, does not.
func TestCaptureTBFailsTheTestOnLeftoverErrors(t *testing.T) {
	left := &recordTB{TB: t}
	c := newCaptureTB(left)
	c.Errorf("read %d", 1)
	if got := c.take(); got != "read 1" {
		t.Fatalf("take() = %q", got)
	}
	c.Errorf("a verdict after the last take(): %s", "missed")
	if len(left.errs) != 0 {
		t.Fatalf("captureTB failed the test at once: %q", left.errs)
	}
	left.runCleanups()
	if len(left.errs) != 1 || !strings.Contains(left.errs[0], "a verdict after the last take(): missed") || strings.Contains(left.errs[0], "read 1") {
		t.Fatalf("leftover error reported as %q", left.errs)
	}

	clean := &recordTB{TB: t}
	c = newCaptureTB(clean)
	c.Error("read")
	c.take()
	clean.runCleanups()
	if len(clean.errs) != 0 {
		t.Fatalf("nothing left, yet the test failed: %q", clean.errs)
	}
}

// E-01, the runner against the real stack: one registered aircraft
// through a PROHIBITED zone and out raises one zone_incursion, cleared
// resolved. Judged with a wrong clear reason and a height violation
// that never came, the runner reports both (a missed alert); judged
// with nothing expected, it reports the raise as a false alert; judged
// right, it reports nothing. A runner that cannot fail proves nothing.
func TestScenarioTheRunnerDetectsAMissAndAFalseAlert(t *testing.T) {
	c := newCaptureTB(t)
	s := ltest.New(c, ltest.Options{Name: "runner-self-test"})
	sd := s.Seed(seed("smoke.json"))
	z := s.ZoneByID(sd, "SMK1")
	ri := standard(t, s)
	rx := s.NewReceiver(s.ReceiverID("rx-self"), z.LatDeg, z.LonDeg-0.01, ri)
	legs := pass(z, 520)
	ac := &ltest.Aircraft{Transmitter: mac(0x5E1), Serial: "TESTSMK000001", OperatorID: "GEOTEST00002501", System: true, Path: ltest.Legs(legs...)}
	f := rx.Fly(ac)
	f.WaitSteps(ltest.Steps(legs...))
	f.Stop()
	s.Await("the clear", 20*time.Second, func() bool { return s.Cleared(violation.KindZoneIncursion, ac.TrackID()) != nil })

	wrong := s.Verify(ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "stale"), ltest.Raise(violation.KindHeight120m, ac.TrackID(), "resolved"))
	got := c.take()
	if wrong.MissedAlerts != 1 || !strings.Contains(got, "cleared resolved, expected stale") || !strings.Contains(got, "missed: height_120m") {
		t.Errorf("wrong expectations: missed %d, reported:\n%s", wrong.MissedAlerts, got)
	}
	none := s.Verify()
	got = c.take()
	if none.FalseAlerts != 1 || !strings.Contains(got, "false alert") {
		t.Errorf("nothing expected: false %d, reported:\n%s", none.FalseAlerts, got)
	}
	right := s.Verify(ltest.Raise(violation.KindZoneIncursion, ac.TrackID(), "resolved").InZone(z.ZoneID()))
	if got := c.take(); right.MissedAlerts != 0 || right.FalseAlerts != 0 || got != "" {
		t.Errorf("right expectations reported:\n%s", got)
	}
	s.CheckIdentity(ri, true)
	if got := c.take(); got != "" {
		t.Errorf("identity: %s", got)
	}
}

// T11: a simulated receiver's batch carries X-Lab-Scenario, and an
// ingest with the production default (LAB_HEADERS_ALLOWED=false)
// refuses every one with 400 lab_header, storing nothing and counting
// the refusals, so a stray simulator never reaches staging data. The
// same receiver without the header is accepted (E-01), and every
// observation is accounted for either way.
func TestScenarioLabHeaderRefusedByAProductionIngest(t *testing.T) {
	s := ltest.New(t, ltest.Options{Name: "lab-header"})
	ri := s.StartRIDIngest(map[string]string{"LAB_HEADERS_ALLOWED": "false"})
	s.StartTSDBWriter(nil)
	const lat, lon = 41.33, 44.62
	rx := s.NewReceiver(s.ReceiverID("rx-lab"), lat, lon, ri)
	ac := &ltest.Aircraft{Transmitter: mac(0x1AB), Serial: "TESTLAB000001", Path: ltest.Hold(lat, lon+0.001, 520)}
	f := rx.Fly(ac)
	f.WaitSteps(4)
	f.Stop()
	tl := rx.Tally()
	if tl.Accepted != 0 || tl.RefusedBy["400 "+receivers.SlugLabHeader] != tl.Sent || tl.Sent < 4 {
		t.Fatalf("with the header: %+v", tl)
	}
	if n := len(s.Rec.Tracks(ac.TrackID())); n != 0 {
		t.Fatalf("%d tracks from refused batches", n)
	}
	ri.WaitLine("status", func(m map[string]any) bool {
		cs, _ := m["counters"].(map[string]any)
		ing, _ := cs["rid_ingest"].(map[string]any)
		n, _ := ing[receivers.ReasonLabHeader].(float64)
		return int(n) == tl.RefusedBatch
	}, 10*time.Second)

	rx.Scenario = ""
	g := rx.Fly(ac)
	g.WaitSteps(4)
	g.Stop()
	s.Await("tracks without the header", 10*time.Second, func() bool { return len(s.Rec.Tracks(ac.TrackID())) >= 4 })
	if tl := rx.Tally(); tl.Accepted < 4 {
		t.Fatalf("without the header: %+v", tl)
	}
	s.Verify()
	s.CheckIdentity(ri, true)
}
