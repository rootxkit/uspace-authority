package picture

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/rootxkit/uspace-authority/internal/policy"
)

// BusWatch: the first check sets the state without a transition; a loss
// calls OnLost with the instant, the return OnBack with the instant the
// bus was lost (the read-back starts there); a steady state calls
// nothing.
func TestBusWatchTransitions(t *testing.T) {
	status := nats.CONNECTED
	var lostAt, backFrom time.Time
	lost, back := 0, 0
	w := &BusWatch{Status: func() nats.Status { return status },
		OnLost: func(at time.Time) { lost++; lostAt = at }, OnBack: func(from time.Time) { back++; backFrom = from }}
	if v := w.View(); !v.Connected {
		t.Fatal("unchecked watch reads as lost")
	}
	t0 := time.Now()
	w.Check(t0)
	w.Check(t0.Add(time.Second))
	if lost != 0 || back != 0 || !w.View().Connected {
		t.Fatalf("steady: lost %d back %d", lost, back)
	}
	status = nats.RECONNECTING
	w.Check(t0.Add(2 * time.Second))
	w.Check(t0.Add(3 * time.Second))
	if v := w.View(); v.Connected || !v.Since.Equal(t0.Add(2*time.Second)) || lost != 1 || !lostAt.Equal(v.Since) {
		t.Fatalf("lost: %+v %d", v, lost)
	}
	status = nats.CONNECTED
	w.Check(t0.Add(4 * time.Second))
	if v := w.View(); !v.Connected || back != 1 || !backFrom.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("back: %+v %d from %v", v, back, backFrom)
	}
	// Started without the bus: lost at once, said, no OnBack until it
	// comes.
	s := &BusWatch{Status: func() nats.Status { return nats.CONNECTING }}
	s.Check(t0)
	if v := s.View(); v.Connected || v.Since.IsZero() {
		t.Fatalf("started without the bus: %+v", v)
	}
}

// Projections: before the first read nothing is claimed; a read gives
// the ages (aged on from the read) and versions, -1 is absent and said;
// a failed read keeps the values and says since when reads fail.
func TestProjectionsView(t *testing.T) {
	var row ProjectionRow
	var fail error
	p := &Projections{Load: func(context.Context) (ProjectionRow, error) { return row, fail }}
	if v := p.View(time.Now()); v.Read || !v.FailingSince.IsZero() || v.RegistryAgeS != nil {
		t.Fatalf("unread: %+v", v)
	}
	row = ProjectionRow{RegistryAgeS: 1.24, RegistryVersion: 3, ZonesAgeS: 2, ZonesVersion: 7, CisVersion: -1, CisAgeS: -1}
	p.Refresh(context.Background())
	v := p.View(time.Now())
	if !v.Read || v.RegistryAgeS == nil || *v.RegistryAgeS < 1.2 || *v.ZonesVersion != "7" || !v.CISAbsent || v.CISVersion != nil || v.RegistryAbsent {
		t.Fatalf("read: %+v", v)
	}
	row = ProjectionRow{RegistryAgeS: -1, RegistryVersion: -1, ZonesVersion: -1, CisVersion: 12, CisAgeS: 30}
	p.Refresh(context.Background())
	v = p.View(time.Now().Add(10 * time.Second))
	if !v.RegistryAbsent || v.ZonesVersion != nil || *v.CISVersion != "12" || *v.CISAgeS < 40 {
		t.Fatalf("read 2: %+v", v)
	}
	fail = errors.New("connection refused")
	p.Refresh(context.Background())
	if v := p.View(time.Now()); v.FailingSince.IsZero() || !v.Read || *v.CISVersion != "12" {
		t.Fatalf("failing: %+v", v)
	}
	if attrs := p.StatusAttrs(); len(attrs) < 2 {
		t.Fatalf("status attrs %v", attrs)
	}
	fail = nil
	p.Refresh(context.Background())
	if v := p.View(time.Now()); !v.FailingSince.IsZero() {
		t.Fatal("failing after a good read")
	}
}

// PolicyOf: the documented defaults as version 0, said, until a policy
// is followed; then the policy's thresholds and version (INV-03).
func TestPolicyOfFollowsThePolicy(t *testing.T) {
	f := policy.NewFollower(nil)
	v := PolicyOf(f)()
	d := policy.Defaults()
	if !v.Default || v.Version != "0" || v.StaleAfterS != d.StaleAfterS || v.LiveMaxAgeS != d.LiveMaxAgeS {
		t.Fatalf("defaults: %+v", v)
	}
	th := policy.Defaults()
	th.StaleAfterS, th.LiveMaxAgeS = 20, 8
	if !f.Apply(policy.Policy{Version: 4, Thresholds: th}) {
		t.Fatal("policy not applied")
	}
	if v := PolicyOf(f)(); v.Default || v.Version != "4" || v.StaleAfterS != 20 || v.LiveMaxAgeS != 8 {
		t.Fatalf("followed: %+v", v)
	}
}
