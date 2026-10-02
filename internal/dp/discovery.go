package dp

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of discovery (E-09).
const (
	CounterSearches            = "isa_searches"
	CounterSearchFailed        = "isa_search_failed"
	CounterSubsCreated         = "subscriptions_created"
	CounterSubsRenewed         = "subscriptions_renewed"
	CounterSubsDeleted         = "subscriptions_deleted"
	CounterSubsFailed          = "subscription_failed"
	CounterSubsRefusedLimit    = "subscriptions_refused_429"
	CounterSubsDeleteFailed    = "subscription_delete_failed"
	CounterTilesOverCap        = "tiles_over_cap"
	CounterDiscoveryNoDSS      = "discovery_without_dss"
	CounterNotificationsUnsub  = "notifications_unknown_subscription"
	CounterSubscriptionsCapped = "subscriptions_over_cap"
)

// DSS states on the status line (02 F7).
const (
	DSSOK           = "ok"
	DSSUnavailable  = "dss_unavailable"
	DSSUnconfigured = "dss_unconfigured"
)

// subscriptionDuration is how long one subscription runs: the F3411
// maximum, NetDSSMaxSubscriptionDurationHours.
const subscriptionDuration = f3411.NetDSSMaxSubscriptionDurationHours * time.Hour

// renewAt is the share of a subscription's life after which it is
// renewed (75 %).
const renewAt = 0.75

// subscription is one DSS subscription of a tile.
type subscription struct {
	id, version string
	start, end  time.Time
}

type tileState struct {
	tile       Tile
	sub        *subscription
	lastSearch time.Time
}

// DSSCalls are the DSS operations discovery makes (Client).
type DSSCalls interface {
	SearchISAs(ctx context.Context, b Box, now, until time.Time) ([]f3411.IdentificationServiceArea, error)
	PutSubscription(ctx context.Context, id, version string, b Box, start, end time.Time, ussBaseURL string) (*f3411.PutSubscriptionResponse, error)
	DeleteSubscription(ctx context.Context, id, version string) error
}

// Discovery keeps, per viewed tile, the ISAs the DSS lists and a DSS
// subscription (≤ 24 h, renewed at 75 %) whose notifications the
// Service Providers post to this system's uss_base_url (02 F7). A tile
// no longer viewed has its subscription deleted. Searches repeat every
// Reread as a repair of a lost notification (G-08). With the DSS
// unreachable the known ISAs stay in use until their time_end, and the
// state says dss_unavailable since when.
type Discovery struct {
	DSS        DSSCalls
	ISAs       *ISAs
	USSBaseURL string
	Reread     time.Duration
	// MaxSubscriptions bounds this system's subscriptions (E-10).
	MaxSubscriptions int
	// Timeout bounds one DSS call.
	Timeout  time.Duration
	Counters *core.Counters
	Limiter  *logging.Limiter
	Now      func() time.Time

	mu          sync.Mutex
	tiles       map[string]*tileState
	state       string
	since       time.Time
	subscribers map[string]string // subscription id -> tile key
}

func (d *Discovery) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Discovery) init() {
	if d.tiles == nil {
		d.tiles, d.subscribers = map[string]*tileState{}, map[string]string{}
	}
	if d.Counters == nil {
		d.Counters = &core.Counters{}
	}
}

// State is the DSS's state and since when.
func (d *Discovery) State() (string, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.DSS == nil {
		return DSSUnconfigured, time.Time{}
	}
	if d.state == "" {
		return DSSOK, time.Time{}
	}
	return d.state, d.since
}

func (d *Discovery) setState(ok bool, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case ok:
		d.state, d.since = DSSOK, now
	case d.state != DSSUnavailable:
		d.state, d.since = DSSUnavailable, now
	}
}

// Known reports whether subscription id is one of this system's.
func (d *Discovery) Known(id string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.subscribers[id]
	return ok
}

// Subscriptions is the number of live subscriptions.
func (d *Discovery) Subscriptions() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.subscribers)
}

// Tiles is the number of tiles discovered.
func (d *Discovery) Tiles() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.tiles)
}

// NewUUID is a random RFC 9562 version 4 UUID (a subscription id).
func NewUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Sync makes the discovered tiles the given ones: a new tile is searched
// and subscribed, a dropped one unsubscribed, a kept one renewed when its
// subscription is 75 % through and searched again every Reread. DSS
// calls run one at a time, each bounded by Timeout, and Sync returns when
// ctx ends.
func (d *Discovery) Sync(ctx context.Context, tiles []Tile) {
	d.mu.Lock()
	d.init()
	want := map[string]Tile{}
	for _, t := range tiles {
		want[t.Key()] = t
	}
	var dropped []*tileState
	for k, st := range d.tiles {
		if _, ok := want[k]; !ok {
			dropped = append(dropped, st)
			delete(d.tiles, k)
		}
	}
	work := make([]*tileState, 0, len(want))
	for k, t := range want {
		st, ok := d.tiles[k]
		if !ok {
			st = &tileState{tile: t}
			d.tiles[k] = st
		}
		work = append(work, st)
	}
	d.mu.Unlock()
	if d.DSS == nil {
		d.Counters.Inc(CounterDiscoveryNoDSS)
		return
	}
	for _, st := range dropped {
		if ctx.Err() != nil {
			return
		}
		d.unsubscribe(ctx, st)
	}
	for _, st := range work {
		if ctx.Err() != nil {
			return
		}
		d.tile(ctx, st)
	}
	d.ISAs.Expire(d.now())
}

func (d *Discovery) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if d.Timeout > 0 {
		return context.WithTimeout(ctx, d.Timeout)
	}
	return context.WithCancel(ctx)
}

// tile searches and subscribes one tile as due.
func (d *Discovery) tile(ctx context.Context, st *tileState) {
	now := d.now()
	if st.sub == nil || !now.Before(st.sub.start.Add(time.Duration(renewAt*float64(st.sub.end.Sub(st.sub.start))))) {
		d.subscribe(ctx, st, now)
	}
	if st.lastSearch.IsZero() || now.Sub(st.lastSearch) >= d.Reread {
		d.search(ctx, st, now)
	}
}

func (d *Discovery) search(ctx context.Context, st *tileState, now time.Time) {
	cctx, cancel := d.bounded(ctx)
	defer cancel()
	d.Counters.Inc(CounterSearches)
	isas, err := d.DSS.SearchISAs(cctx, st.tile.Box, now, now.Add(time.Minute))
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		d.Counters.Inc(CounterSearchFailed)
		d.setState(false, now)
		d.warn("dp_isa_search", "ISA search failed; the known ISAs stay in use until their time_end (dss_unavailable)", err)
		return
	}
	d.setState(true, now)
	st.lastSearch = now
	d.ISAs.FromSearch(st.tile.Key(), isas)
}

func (d *Discovery) subscribe(ctx context.Context, st *tileState, now time.Time) {
	if d.USSBaseURL == "" {
		return
	}
	id, version := NewUUID(), ""
	if st.sub != nil {
		id, version = st.sub.id, st.sub.version
	} else if d.MaxSubscriptions > 0 && d.Subscriptions() >= d.MaxSubscriptions {
		d.Counters.Inc(CounterSubscriptionsCapped)
		d.warn("dp_subscriptions_capped", "subscription bound reached; the tile is searched every reread only", nil)
		return
	}
	cctx, cancel := d.bounded(ctx)
	defer cancel()
	end := now.Add(subscriptionDuration)
	resp, err := d.DSS.PutSubscription(cctx, id, version, st.tile.Box, now, end, d.USSBaseURL)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		if StatusOf(err) == http.StatusTooManyRequests {
			d.Counters.Inc(CounterSubsRefusedLimit)
		} else {
			d.Counters.Inc(CounterSubsFailed)
		}
		if StatusOf(err) == 0 {
			d.setState(false, now)
		}
		d.warn("dp_subscription", "DSS subscription not created or renewed; the tile is searched every reread", err)
		return
	}
	d.setState(true, now)
	if version == "" {
		d.Counters.Inc(CounterSubsCreated)
	} else {
		d.Counters.Inc(CounterSubsRenewed)
	}
	sub := &subscription{id: id, version: resp.Subscription.Version, start: now, end: end}
	if ts := resp.Subscription.TimeStart; ts != nil && !ts.Value.IsZero() {
		sub.start = ts.Value
	}
	if te := resp.Subscription.TimeEnd; te != nil && !te.Value.IsZero() {
		sub.end = te.Value
	}
	st.sub = sub
	d.mu.Lock()
	d.subscribers[id] = st.tile.Key()
	d.mu.Unlock()
	if resp.ServiceAreas != nil {
		d.ISAs.FromSearch(st.tile.Key(), *resp.ServiceAreas)
		st.lastSearch = now
	}
}

func (d *Discovery) unsubscribe(ctx context.Context, st *tileState) {
	if st.sub == nil {
		return
	}
	d.mu.Lock()
	delete(d.subscribers, st.sub.id)
	d.mu.Unlock()
	cctx, cancel := d.bounded(ctx)
	defer cancel()
	if err := d.DSS.DeleteSubscription(cctx, st.sub.id, st.sub.version); err != nil {
		// The subscription runs out by its time_end (at most 24 h).
		d.Counters.Inc(CounterSubsDeleteFailed)
		d.warn("dp_subscription_delete", "subscription of a tile no longer viewed not deleted; it ends at its time_end", err)
		return
	}
	d.Counters.Inc(CounterSubsDeleted)
}

// Close deletes every subscription (the drain).
func (d *Discovery) Close(ctx context.Context) {
	d.mu.Lock()
	all := make([]*tileState, 0, len(d.tiles))
	for _, st := range d.tiles {
		all = append(all, st)
	}
	d.tiles = map[string]*tileState{}
	d.mu.Unlock()
	if d.DSS == nil {
		return
	}
	for _, st := range all {
		d.unsubscribe(ctx, st)
	}
}

func (d *Discovery) warn(key, msg string, err error) {
	if d.Limiter == nil {
		return
	}
	attrs := []any{}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	d.Limiter.Limited(key).Warn(msg, attrs...)
}
