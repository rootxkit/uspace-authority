package dp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/f3411"
)

// Audit A-B3 (a), E-01: an ISA learned from a notification is trusted
// for NotifiedMaxLifetime at most: a time_end beyond it is capped,
// counted, and the ISA expires there; one within it keeps its time_end.
func TestNotifiedISALifetimeIsCapped(t *testing.T) {
	clk := &clock{t: t0}
	s := &ISAs{Max: 10, Now: clk.now, NotifiedMaxLifetime: 24 * time.Hour}
	far := isa("isa-far", "ussp-a-01", spBase)
	far.TimeEnd.Value = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	near := isa("isa-near", "ussp-a-01", spBase)
	ext := Volume(box2km, t0.Add(-time.Hour), t0.Add(time.Hour))
	s.Notify("isa-far", &far, &ext)
	s.Notify("isa-near", &near, &ext)
	if s.Counters.Snapshot()[CounterISAsLifetimeCapped] != 1 {
		t.Fatalf("not counted: %v", s.Counters.Snapshot())
	}
	s.Expire(t0.Add(2 * time.Hour))
	if s.Len() != 1 {
		t.Fatalf("the ISA within the bound did not keep its time_end: %d held", s.Len())
	}
	s.Expire(t0.Add(24*time.Hour + time.Second))
	if s.Len() != 0 {
		t.Fatalf("a notified time_end in 2099 is trusted past the bound: %d held", s.Len())
	}
}

// Audit A-B3 (b), E-01: a notification-only ISA is provisional. A DSS
// search of a tile its extent meets that does not list it drops it; one
// the search lists is kept, and one whose extent the searched tile does
// not meet is not touched.
func TestSearchDropsUnlistedNotifiedISAs(t *testing.T) {
	clk := &clock{t: t0}
	s := &ISAs{Max: 10, Now: clk.now}
	tiles, _ := TilesOf(box2km, f3411.NetMaxDisplayAreaDiagonalKm, 10)
	in := Volume(box2km, t0.Add(-time.Hour), t0.Add(time.Hour))
	far := Volume(Box{MinLat: 10, MinLon: 10, MaxLat: 10.01, MaxLon: 10.01}, t0.Add(-time.Hour), t0.Add(time.Hour))
	for _, id := range []string{"isa-unlisted", "isa-listed"} {
		a := isa(id, "ussp-a-01", spBase)
		s.Notify(id, &a, &in)
	}
	elsewhere := isa("isa-elsewhere", "ussp-a-01", spBase)
	s.Notify("isa-elsewhere", &elsewhere, &far)
	s.FromSearch(tiles[0].Key(), []f3411.IdentificationServiceArea{isa("isa-listed", "ussp-a-01", spBase)})
	if _, ok := s.Owner("isa-unlisted"); ok {
		t.Fatal("a notified ISA the DSS does not list in a tile it meets is still held")
	}
	if _, ok := s.Owner("isa-listed"); !ok {
		t.Fatal("a listed ISA was dropped")
	}
	if _, ok := s.Owner("isa-elsewhere"); !ok {
		t.Fatal("a notified ISA outside the searched tile was dropped")
	}
	if s.Counters.Snapshot()[CounterISAsUnconfirmed] != 1 {
		t.Fatalf("not counted: %v", s.Counters.Snapshot())
	}
}

// Audit A-B3 (c, d), E-10: notification-only ISAs drive the providers
// past DP_MAX_PROVIDERS; once the DSS search lists another Service
// Provider and not them, that Service Provider is still polled (a
// provider no confirmed ISA names gives way), and providers no ISA
// names are forgotten after ProviderForgetAfter.
func TestProviderCapCannotBeFilledByNotificationsAlone(t *testing.T) {
	clk := &clock{t: t0}
	sp := &fakeSP{respTS: t0}
	e := engine(t, sp, &recorder{}, clk)
	e.ISAs.Now = clk.now
	e.S.MaxProviders = 3
	e.S.ProviderForgetAfter = time.Minute
	e.Views = func(context.Context) []Box { return []Box{box2km} }
	tiles, _ := TilesOf(box2km, f3411.NetMaxDisplayAreaDiagonalKm, 10)
	ext := Volume(box2km, t0.Add(-time.Hour), t0.Add(time.Hour))
	for i := range 5 {
		id := fmt.Sprintf("isa-spam-%d", i)
		a := isa(id, "ussp-spam-01", fmt.Sprintf("https://spam%d.example.test", i))
		e.ISAs.Notify(id, &a, &ext)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); e.wg.Wait() }()
	e.Reconcile(ctx)
	if len(e.Providers()) != 3 || e.Counters.Snapshot()[CounterProvidersOverCap] == 0 {
		t.Fatalf("providers %d, over cap %d", len(e.Providers()), e.Counters.Snapshot()[CounterProvidersOverCap])
	}
	e.ISAs.FromSearch(tiles[0].Key(), []f3411.IdentificationServiceArea{isa("isa-real", "ussp-lab-01", spBase)})
	e.Reconcile(ctx)
	found := false
	for _, p := range e.Providers() {
		if p.BaseURL == spBase {
			found = true
		}
	}
	if !found {
		t.Fatalf("the DSS-listed Service Provider is not polled: %d providers", len(e.Providers()))
	}
	if e.Counters.Snapshot()[CounterProvidersEvicted] == 0 {
		t.Fatalf("eviction not counted: %v", e.Counters.Snapshot())
	}
	// The unnamed providers are forgotten after ProviderForgetAfter.
	clk.add(2 * time.Minute)
	e.Reconcile(ctx)
	if len(e.Providers()) != 1 || e.Providers()[0].BaseURL != spBase {
		t.Fatalf("providers no ISA names are not forgotten: %d", len(e.Providers()))
	}
	if e.Counters.Snapshot()[CounterProvidersForgotten] == 0 {
		t.Fatalf("forgetting not counted: %v", e.Counters.Snapshot())
	}
}
