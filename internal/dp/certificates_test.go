package dp

import (
	"context"
	"testing"

	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/certkv"
)

// WP-16, E-01: a Service Provider whose owner is on the register is
// known; the register republished without it (a suspension) makes it
// provider_unknown at the next reconcile, counted once, still polled;
// back on the register, it is known again.
func TestProviderFollowsTheCertificateRegister(t *testing.T) {
	sp := &fakeSP{respTS: t0}
	e := engine(t, sp, &recorder{}, &clock{t: t0})
	reader := &CertificateReader{}
	e.Certified = reader.Certified
	e.Views = func(context.Context) []Box { return []Box{box2km} }
	tile, _ := TilesOf(box2km, f3411.NetMaxDisplayAreaDiagonalKm, 10)
	e.ISAs.FromSearch(tile[0].Key(), []f3411.IdentificationServiceArea{isa("isa-1", "ussp-AB12-01", spBase)})
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); e.wg.Wait() }()

	// Nothing read yet: unknown, and the status line says so.
	e.Reconcile(ctx)
	p := e.Providers()[0]
	if p.Known() || p.Counters.Snapshot()[CounterProviderUnknown] != 1 {
		t.Fatalf("known %v counters %v", p.Known(), p.Counters.Snapshot())
	}
	if a := reader.StatusAttrs(); len(a) != 1 || a[0].Value.Bool() {
		t.Fatalf("status %v", a)
	}
	certified := certkv.Register{Version: 1, USSPs: []certkv.USSP{{ClientID: "ussp-AB12-01", Code: "AB12", BaseURL: spBase, Status: "operating"}}}
	if !reader.Apply(certified) {
		t.Fatal("not applied")
	}
	e.Reconcile(ctx)
	if !p.Known() {
		t.Fatal("not known on the register")
	}
	reader.Apply(certkv.Register{Version: 2})
	e.Reconcile(ctx)
	if p.Known() || p.Counters.Snapshot()[CounterProviderUnknown] != 2 || e.Pollers() != 1 {
		t.Fatalf("after the suspension: known %v counters %v pollers %d", p.Known(), p.Counters.Snapshot(), e.Pollers())
	}
	e.Reconcile(ctx)
	if p.Counters.Snapshot()[CounterProviderUnknown] != 2 {
		t.Fatal("an unchanged state counted again")
	}
	// An older register is ignored and counted.
	if reader.Apply(certified) || reader.Counters != nil {
		t.Fatal("an older register replaced a newer one")
	}
	certified.Version = 3
	reader.Apply(certified)
	e.Reconcile(ctx)
	if !p.Known() {
		t.Fatal("not known after the reinstatement")
	}
}
