package dp_test

import (
	"context"
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
