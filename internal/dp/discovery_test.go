package dp_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/ltest/fakedss"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func discovery(dss *fakedss.DSS, clk *clock, sub string) (*dp.Discovery, *dp.ISAs) {
	isas := &dp.ISAs{Max: 100, Counters: &core.Counters{}}
	c := &dp.Client{Tokens: nil, MaxBody: 1 << 20, DSS: dss.URL()}
	d := &dp.Discovery{DSS: c, ISAs: isas, USSBaseURL: sub, Reread: 30 * time.Second, MaxSubscriptions: 10,
		Timeout: 2 * time.Second, Counters: &core.Counters{}, Now: clk.now}
	return d, isas
}

// 02 F7: a viewed tile is searched and subscribed (one subscription per
// tile, 24 h, this system's uss_base_url); the subscription is renewed
// once 75 % of it has run, not before; a tile no longer viewed has its
// subscription deleted.
func TestDiscoverySubscribesRenewsAndDeletes(t *testing.T) {
	dss := fakedss.NewDSS()
	defer dss.Close()
	now := time.Now().UTC()
	clk := &clock{t: now}
	d, isas := discovery(dss, clk, "https://authority.example.test")
	d.DSS.(*dp.Client).Tokens = newIssuer(t)
	dss.PutISA("isa-1", "ussp-lab-01", "https://sp.example.test", box, now.Add(-time.Minute), now.Add(time.Hour))
	tile := dp.Tile{Box: box}
	d.Sync(context.Background(), []dp.Tile{tile})
	subs := dss.Subscriptions()
	if len(subs) != 1 || d.Subscriptions() != 1 {
		t.Fatalf("subscriptions %v", subs)
	}
	for id, s := range subs {
		if !d.Known(id) || s[2] != "https://authority.example.test" {
			t.Fatalf("subscription %s %v", id, s)
		}
	}
	if got := isas.ForTile(tile, now); len(got) != 1 {
		t.Fatalf("ISAs %+v", got)
	}
	_, puts, _ := dss.Counts()
	clk.add(17 * time.Hour) // 71 %: not yet
	d.Sync(context.Background(), []dp.Tile{tile})
	if _, p, _ := dss.Counts(); p != puts {
		t.Fatal("renewed before 75 %")
	}
	clk.add(time.Hour + time.Minute) // past 75 %
	d.Sync(context.Background(), []dp.Tile{tile})
	if _, p, _ := dss.Counts(); p != puts+1 || d.Counters.Snapshot()[dp.CounterSubsRenewed] != 1 {
		t.Fatalf("not renewed at 75 %%: puts %d, counters %v", p, d.Counters.Snapshot())
	}
	d.Sync(context.Background(), nil)
	if _, _, del := dss.Counts(); del != 1 || len(dss.Subscriptions()) != 0 || d.Subscriptions() != 0 {
		t.Fatalf("not deleted: %v", dss.Subscriptions())
	}
}

// 02 F7, E-02: with the DSS unreachable the known ISAs stay in use until
// their time_end and the state says dss_unavailable since when; once
// past time_end they are forgotten. Back, the state is ok.
func TestDSSDownKeepsKnownISAsUntilTheirEnd(t *testing.T) {
	dss := fakedss.NewDSS()
	defer dss.Close()
	now := time.Now().UTC()
	clk := &clock{t: now}
	d, isas := discovery(dss, clk, "")
	d.DSS.(*dp.Client).Tokens = newIssuer(t)
	dss.PutISA("isa-1", "ussp-lab-01", "https://sp.example.test", box, now.Add(-time.Minute), now.Add(10*time.Minute))
	tile := dp.Tile{Box: box}
	d.Sync(context.Background(), []dp.Tile{tile})
	if st, _ := d.State(); st != dp.DSSOK || len(isas.ForTile(tile, clk.now())) != 1 {
		t.Fatalf("state %s", st)
	}
	dss.SetDown(true)
	clk.add(time.Minute)
	d.Sync(context.Background(), []dp.Tile{tile})
	st, since := d.State()
	if st != dp.DSSUnavailable || !since.Equal(clk.now()) || len(isas.ForTile(tile, clk.now())) != 1 {
		t.Fatalf("down: state %s since %v ISAs %d", st, since, len(isas.ForTile(tile, clk.now())))
	}
	clk.add(10 * time.Minute)
	d.Sync(context.Background(), []dp.Tile{tile})
	if n := len(isas.ForTile(tile, clk.now())); n != 0 || isas.Len() != 0 {
		t.Fatalf("an ISA past its time_end is still used (%d)", n)
	}
	dss.SetDown(false)
	clk.add(time.Minute)
	d.Sync(context.Background(), []dp.Tile{tile})
	if st, _ := d.State(); st != dp.DSSOK {
		t.Fatalf("back: %s", st)
	}
}

// Without a DSS nothing is discovered and the state says so.
func TestDiscoveryWithoutDSSSaysSo(t *testing.T) {
	d := &dp.Discovery{ISAs: &dp.ISAs{}, Counters: &core.Counters{}}
	d.Sync(context.Background(), []dp.Tile{{Box: box}})
	if st, _ := d.State(); st != dp.DSSUnconfigured || d.Counters.Snapshot()[dp.CounterDiscoveryNoDSS] != 1 {
		t.Fatalf("%s %v", st, d.Counters.Snapshot())
	}
}

// E-01, end to end over HTTP: the fake Service Provider posts an ISA
// change to the subscriber the fake DSS names, with a token for this
// host granting rid.service_provider: applied. The same posted with
// another host's aud is refused (401) and changes nothing.
func TestNotificationPostedByTheServiceProvider(t *testing.T) {
	dss := fakedss.NewDSS()
	defer dss.Close()
	iss := newIssuer(t)
	isas := &dp.ISAs{Max: 10, Counters: &core.Counters{}}
	n := &dp.Notifications{Verifier: iss.verifier(t, "127.0.0.1"), ISAs: isas, MaxBytes: 64 << 10, Counters: &core.Counters{}}
	mux := http.NewServeMux()
	n.Mount(mux)
	dpSrv := httptest.NewServer(mux)
	defer dpSrv.Close()

	now := time.Now().UTC()
	clk := &clock{t: now}
	d, _ := discovery(dss, clk, dpSrv.URL)
	d.DSS.(*dp.Client).Tokens = iss
	d.Sync(context.Background(), []dp.Tile{{Box: box}})
	subscribers := dss.PutISA("isa-2", "ussp-lab-01", "https://sp.example.test", box, now, now.Add(time.Hour))
	if len(subscribers) != 1 || subscribers[0].Url != dpSrv.URL {
		t.Fatalf("subscribers %+v", subscribers)
	}
	area, _ := dss.ISA("isa-2")
	ext := dp.Volume(box, now, now.Add(time.Hour))
	other, err := fakedss.Notify(context.Background(), subscribers, "isa-2", &area, &ext, func(string) string {
		return iss.issue("ussp-lab-01", "other.example.test", string(f3411.ScopeServiceProvider))
	})
	if err != nil || other[dpSrv.URL] != http.StatusUnauthorized || isas.Len() != 0 {
		t.Fatalf("another host's aud: %v %v, %d ISAs", other, err, isas.Len())
	}
	ok, err := fakedss.Notify(context.Background(), subscribers, "isa-2", &area, &ext, func(string) string {
		return iss.issue("ussp-lab-01", "127.0.0.1", string(f3411.ScopeServiceProvider))
	})
	if err != nil || ok[dpSrv.URL] != http.StatusNoContent || isas.Len() != 1 {
		t.Fatalf("own aud: %v %v, %d ISAs", ok, err, isas.Len())
	}
}

// Audit A-S4, E-01: a renewal the DSS refuses because it no longer holds
// the subscription (404, or 409 for the version) is not retried for
// ever: the subscription is forgotten, counted, and the next sync makes
// a new one; a renewal the DSS accepts keeps the id.
func TestDiscoveryRemakesASubscriptionWhoseRenewalIsRefused(t *testing.T) {
	dss := fakedss.NewDSS()
	defer dss.Close()
	now := time.Now().UTC()
	clk := &clock{t: now}
	d, _ := discovery(dss, clk, "https://authority.example.test")
	d.DSS.(*dp.Client).Tokens = newIssuer(t)
	tile := dp.Tile{Box: box}
	d.Sync(context.Background(), []dp.Tile{tile})
	var first string
	for id := range dss.Subscriptions() {
		first = id
	}
	clk.add(19 * time.Hour) // past 75 %: renewed, same id
	d.Sync(context.Background(), []dp.Tile{tile})
	if _, ok := dss.Subscriptions()[first]; !ok || d.Counters.Snapshot()[dp.CounterSubsRenewed] != 1 || !d.Known(first) {
		t.Fatalf("an accepted renewal: %v %v", dss.Subscriptions(), d.Counters.Snapshot())
	}
	dss.DropSubscriptions()
	clk.add(19 * time.Hour)
	d.Sync(context.Background(), []dp.Tile{tile})
	if d.Counters.Snapshot()[dp.CounterSubsLost] != 1 || d.Known(first) {
		t.Fatalf("the refused renewal: counters %v, still known %v", d.Counters.Snapshot(), d.Known(first))
	}
	clk.add(time.Second)
	d.Sync(context.Background(), []dp.Tile{tile})
	subs := dss.Subscriptions()
	if len(subs) != 1 || d.Subscriptions() != 1 {
		t.Fatalf("no new subscription: %v", subs)
	}
	for id := range subs {
		if id == first || !d.Known(id) {
			t.Fatalf("subscription %s (first %s)", id, first)
		}
	}
}

// scriptedDSS fails every call for a box in fail and answers the rest.
type scriptedDSS struct {
	mu   sync.Mutex
	fail map[dp.Box]bool
}

func (s *scriptedDSS) failing(b dp.Box) bool { s.mu.Lock(); defer s.mu.Unlock(); return s.fail[b] }

func (s *scriptedDSS) set(b dp.Box, fail bool) { s.mu.Lock(); defer s.mu.Unlock(); s.fail[b] = fail }

func (s *scriptedDSS) SearchISAs(_ context.Context, b dp.Box, _, _ time.Time) ([]f3411.IdentificationServiceArea, error) {
	if s.failing(b) {
		return nil, errDSSDown
	}
	return nil, nil
}

// PutSubscription is never called: the test's discovery has no
// uss_base_url, so it searches only.
func (s *scriptedDSS) PutSubscription(context.Context, string, string, dp.Box, time.Time, time.Time, string) (*f3411.PutSubscriptionResponse, error) {
	return nil, errDSSDown
}

func (s *scriptedDSS) DeleteSubscription(context.Context, string, string) error { return nil }

var errDSSDown = errors.New("connection refused")

// The DSS's state is every viewed tile's, not the last call's: one tile
// whose search keeps failing keeps it dss_unavailable since its first
// failure, whatever order the tiles are searched in and however many
// others answer (a later success masked it before). The tile recovering,
// or leaving the view, makes it ok.
func TestDiscoveryStateAggregatesEveryTile(t *testing.T) {
	now := time.Now().UTC()
	clk := &clock{t: now}
	a, b := dp.Box{MinLat: 41.70, MinLon: 44.80, MaxLat: 41.71, MaxLon: 44.81}, dp.Box{MinLat: 41.72, MinLon: 44.80, MaxLat: 41.73, MaxLon: 44.81}
	dss := &scriptedDSS{fail: map[dp.Box]bool{a: true}}
	d := &dp.Discovery{DSS: dss, ISAs: &dp.ISAs{Max: 100, Counters: &core.Counters{}}, Reread: time.Second, MaxSubscriptions: 10, Counters: &core.Counters{}, Now: clk.now}
	tiles := []dp.Tile{{Box: a}, {Box: b}}
	first := now
	for range 5 {
		d.Sync(context.Background(), tiles)
		if st, since := d.State(); st != dp.DSSUnavailable || !since.Equal(first) {
			t.Fatalf("tile a failing, b answering: %s since %v, want dss_unavailable since %v", st, since, first)
		}
		clk.add(2 * time.Second)
	}
	// Absence: every tile answering is ok.
	dss.set(a, false)
	d.Sync(context.Background(), tiles)
	if st, since := d.State(); st != dp.DSSOK || since.IsZero() {
		t.Fatalf("every tile answering: %s %v", st, since)
	}
	// a fails again, then leaves the view: ok.
	clk.add(2 * time.Second)
	dss.set(a, true)
	d.Sync(context.Background(), tiles)
	if st, _ := d.State(); st != dp.DSSUnavailable {
		t.Fatalf("a failing again: %s", st)
	}
	clk.add(2 * time.Second)
	d.Sync(context.Background(), []dp.Tile{{Box: b}})
	if st, _ := d.State(); st != dp.DSSOK {
		t.Fatalf("the failing tile no longer viewed: %s", st)
	}
}
