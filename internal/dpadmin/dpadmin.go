// Package dpadmin is api's administration of the F3411 Display Provider
// (WP-14, docs/PLAN.md §5 "DP administration"; admin only):
//
//   - the oversight areas (dp_views): POST /v1/dp/views writes the row
//     and its events row in one transaction and, after the commit, every
//     area to KV bucket dp_oversight with the table's version, never
//     replacing a higher one (internal/dpviews.PutOversight, compare and
//     set: two api replicas never move it back); Republish repeats it
//     periodically, repairing a lost bucket (G-08);
//   - the Service Providers seen: dp-poller's last
//     src.v1.network_rid.<uss_id> statuses, bounded (E-10);
//   - USS availability arbitration at the DSS (F3548
//     utm.availability_arbitration), recorded before the call and with
//     its outcome after it, one arbitration per USS at a time across
//     replicas (an advisory lock).
//
// dp-poller never opens the relational database (B-15); everything it
// needs of this package travels in KV.
package dpadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dp/utmapi"
	"github.com/rootxkit/uspace-authority/internal/dpviews"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Events of the package (internal/audit catalogue).
const (
	EventViewCreated           = audit.EventDPViewCreated
	EventAvailabilityRequested = audit.EventDPAvailabilityRequested
	EventAvailabilitySet       = audit.EventDPAvailabilitySet
	EventAvailabilityFailed    = audit.EventDPAvailabilityFailed
)

// Problem slugs.
const (
	SlugTooManyViews    = "dp_views_full"
	SlugArbitrationBusy = "arbitration_in_progress"
	SlugDSS             = "dss_refused"
	SlugNoDSS           = "dss_unconfigured"
)

// Counters (E-09).
const (
	CounterViewsCreated       = "views_created"
	CounterViewsPublished     = "views_published"
	CounterViewsPublishFailed = "views_publish_failed"
	CounterViewsBucketAhead   = "views_bucket_ahead"
	CounterArbitrations       = "arbitrations"
	CounterArbitrationsFailed = "arbitrations_failed"
	CounterStatusMalformed    = "provider_status_malformed"
	CounterStatusEvicted      = "provider_status_evicted"
)

// DSSTokens gives the bearer token for the DSS (tokens.Client).
type DSSTokens interface {
	Token(ctx context.Context, baseURL string, scopes ...string) (string, error)
}

// ScopeArbitration is the F3548 scope of availability arbitration.
const ScopeArbitration = "utm.availability_arbitration"

// Service is the package's state.
type Service struct {
	DB    *pgstore.DB
	Audit *audit.Writer
	// Oversight opens the dp_oversight bucket; nil publishes nothing.
	Oversight func(ctx context.Context) (jetstream.KeyValue, error)
	// KVTimeout bounds one publication.
	KVTimeout time.Duration
	// DSS is the DSS base URL (F3548 under /dss/v1); empty refuses
	// arbitration with 503 dss_unconfigured.
	DSS        string
	Tokens     DSSTokens
	HTTPClient *http.Client
	// Providers are dp-poller's statuses.
	Providers *Providers
	// StaleAfter is SOURCE_STATUS_STALE_S.
	StaleAfter time.Duration
	Counters   *core.Counters
	Logger     *slog.Logger
	Limiter    *logging.Limiter
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return logging.Discard()
}

func viewOut(r pggen.DpView) gen.DPView {
	return gen.DPView{Id: r.ID, Label: r.Label, Bbox: []float64{r.WestDeg, r.SouthDeg, r.EastDeg, r.NorthDeg},
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt.UTC()}
}

// ListDPViews lists the oversight areas.
func (s *Service) ListDPViews(ctx context.Context, _ gen.ListDPViewsRequestObject) (gen.ListDPViewsResponseObject, error) {
	rows, err := s.DB.Queries().ListDPViews(ctx, dpviews.MaxOversight)
	if err != nil {
		return nil, err
	}
	out := gen.DPViewList{Views: make([]gen.DPView, 0, len(rows))}
	for _, r := range rows {
		out.Views = append(out.Views, viewOut(r))
	}
	return gen.ListDPViews200JSONResponse(out), nil
}

// CreateDPView adds an oversight area, audited, and publishes the
// areas after the commit.
func (s *Service) CreateDPView(ctx context.Context, req gen.CreateDPViewRequestObject) (gen.CreateDPViewResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	label := strings.TrimSpace(req.Body.Label)
	if label == "" || len(label) > 200 {
		return nil, core.Fieldf("label", "1 to 200 characters")
	}
	if len(req.Body.Bbox) != 4 {
		return nil, core.Fieldf("bbox", "four numbers [west, south, east, north]")
	}
	box := dpviews.BBox{req.Body.Bbox[0], req.Body.Bbox[1], req.Body.Bbox[2], req.Body.Bbox[3]}
	if err := box.Check(); err != nil {
		return nil, err
	}
	var row pggen.DpView
	err = s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockViews); err != nil {
			return err
		}
		n, err := q.CountDPViews(ctx)
		if err != nil {
			return err
		}
		if n >= dpviews.MaxOversight {
			return httpx.Refuse(http.StatusConflict, SlugTooManyViews, fmt.Sprintf("at most %d oversight areas", dpviews.MaxOversight))
		}
		row, err = q.InsertDPView(ctx, pggen.InsertDPViewParams{Label: label, WestDeg: box[0], SouthDeg: box[1], EastDeg: box[2],
			NorthDeg: box[3], CreatedBy: actor.ID})
		if err != nil {
			return err
		}
		_, err = s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: "dp_view", EntityID: fmt.Sprint(row.ID),
			EventType: EventViewCreated, Payload: map[string]any{"label": label, "bbox": box}})
		return err
	})
	if err != nil {
		return nil, err
	}
	s.Counters.Inc(CounterViewsCreated)
	// After the commit: a failed publication is repaired by Republish.
	if err := s.Republish(context.WithoutCancel(ctx)); err != nil {
		s.Limiter.Limited("dp_views_publish").Warn("oversight areas not published; the periodic republish retries",
			slog.String("error", err.Error()))
	}
	return gen.CreateDPView201JSONResponse(viewOut(row)), nil
}

// lockViews serialises the writers of the areas.
var lockViews = pgstore.LockKey("dp_views")

// Republish publishes every area with the table's version (its newest
// id) unless the bucket holds a higher one.
func (s *Service) Republish(ctx context.Context) error {
	if s.Oversight == nil {
		return nil
	}
	rows, err := s.DB.Queries().ListDPViews(ctx, dpviews.MaxOversight)
	if err != nil {
		s.Counters.Inc(CounterViewsPublishFailed)
		return err
	}
	o := dpviews.Oversight{Areas: make([]dpviews.Area, 0, len(rows))}
	for _, r := range rows {
		o.Areas = append(o.Areas, dpviews.Area{ID: r.ID, Label: r.Label, BBox: dpviews.BBox{r.WestDeg, r.SouthDeg, r.EastDeg, r.NorthDeg}})
		o.Version = max(o.Version, r.ID)
	}
	if s.KVTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.KVTimeout)
		defer cancel()
	}
	kv, err := s.Oversight(ctx)
	if err != nil {
		s.Counters.Inc(CounterViewsPublishFailed)
		return err
	}
	stored, err := dpviews.PutOversight(ctx, kv, o, 3)
	switch {
	case err != nil:
		s.Counters.Inc(CounterViewsPublishFailed)
		return err
	case !stored:
		s.Counters.Inc(CounterViewsBucketAhead)
	default:
		s.Counters.Inc(CounterViewsPublished)
	}
	return nil
}

// RunRepublish republishes every interval until ctx ends.
func (s *Service) RunRepublish(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := s.Republish(ctx); err != nil && ctx.Err() == nil {
			s.Limiter.Limited("dp_views_republish").Warn("oversight areas not republished", slog.String("error", err.Error()))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Providers keeps dp-poller's last src.v1.network_rid status per
// Service Provider, at most Max (past it the one heard longest ago is
// dropped and counted, E-10).
type Providers struct {
	Max      int
	Counters *core.Counters
	Now      func() time.Time

	mu   sync.Mutex
	last map[string]providerStatus
}

type providerStatus struct {
	body dp.StatusBody
	at   time.Time
}

func (p *Providers) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Offer takes one src.v1.network_rid.> message.
func (p *Providers) Offer(raw []byte) {
	var env bus.Envelope[dp.StatusBody]
	if err := json.Unmarshal(raw, &env); err != nil || env.Schema != dp.StatusSchema || env.Body.Source != dp.SourceType ||
		env.Body.SourceInstance == nil || *env.Body.SourceInstance == "" {
		if p.Counters != nil {
			p.Counters.Inc(CounterStatusMalformed)
		}
		return
	}
	id := *env.Body.SourceInstance
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil {
		p.last = map[string]providerStatus{}
	}
	if _, ok := p.last[id]; !ok && p.Max > 0 && len(p.last) >= p.Max {
		var oldest string
		var at time.Time
		for k := range p.last {
			if v := p.last[k].at; oldest == "" || v.Before(at) {
				oldest, at = k, v
			}
		}
		delete(p.last, oldest)
		if p.Counters != nil {
			p.Counters.Inc(CounterStatusEvicted)
		}
	}
	p.last[id] = providerStatus{body: env.Body, at: p.now()}
}

// Run subscribes to src.v1.network_rid.> until ctx ends.
func (p *Providers) Run(ctx context.Context, nc *nats.Conn, logger *slog.Logger) {
	ch := make(chan *nats.Msg, 256)
	for ctx.Err() == nil {
		sub, err := nc.ChanSubscribe("src.v1."+dp.SourceType+".>", ch)
		if err == nil {
			for {
				select {
				case <-ctx.Done():
					_ = sub.Unsubscribe()
					return
				case m := <-ch:
					p.Offer(m.Data)
				}
			}
		}
		logger.Debug("provider status subscription unavailable; retrying", slog.String("error", err.Error()))
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
}

func parseStamp(s *string) *time.Time {
	if s == nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, *s)
	if err != nil {
		return nil
	}
	return &t
}

// List is every provider, by id.
func (p *Providers) List(staleAfter time.Duration) []gen.DPProvider {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	ids := make([]string, 0, len(p.last))
	for id := range p.last {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]gen.DPProvider, 0, len(ids))
	for _, id := range ids {
		st := p.last[id]
		b := &st.body
		age := now.Sub(st.at).Seconds()
		v := gen.DPProvider{UssId: id, State: gen.DPProviderState(b.State), Isas: b.ISAs, Tiles: b.Tiles, Flights: b.Flights,
			Slow: b.Slow, ProviderUnknown: b.ProviderUnknown, StatusAgeS: age, AgeS: b.AgeS, DisabledBy: b.DisabledBy,
			DisabledByWho: b.DisabledByWho, Since: parseStamp(&b.Since), UnavailableSince: parseStamp(b.UnavailableSince)}
		if staleAfter > 0 && now.Sub(st.at) > staleAfter && b.State != dp.StateDisabled {
			// dp-poller is silent: what it said last is not current.
			v.State = gen.DPProviderState(dp.StateStale)
		}
		if b.USSBaseURL != "" {
			u := b.USSBaseURL
			v.UssBaseUrl = &u
		}
		p95, p99 := b.P95S, b.P99S
		v.P95S, v.P99S = &p95, &p99
		if b.DSS != "" {
			d := gen.DPProviderDss(b.DSS)
			v.Dss = &d
		}
		counters := make(map[string]int64, len(b.Counters))
		for k, n := range b.Counters {
			counters[k] = int64(n)
		}
		v.Counters = &counters
		out = append(out, v)
	}
	return out
}

// ListDPProviders answers dp-poller's statuses.
func (s *Service) ListDPProviders(context.Context, gen.ListDPProvidersRequestObject) (gen.ListDPProvidersResponseObject, error) {
	out := gen.DPProviderList{Providers: []gen.DPProvider{}}
	if s.Providers != nil {
		out.Providers = s.Providers.List(s.StaleAfter)
	}
	return gen.ListDPProviders200JSONResponse(out), nil
}

var ussIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// maxDSSBody bounds a DSS answer read.
const maxDSSBody = 64 << 10

// SetDPProviderAvailability arbitrates a USS's availability at the DSS:
// recorded (committed) before the call, the call made with this USS's
// arbitration held by an advisory lock, the outcome recorded after it.
func (s *Service) SetDPProviderAvailability(ctx context.Context, req gen.SetDPProviderAvailabilityRequestObject) (gen.SetDPProviderAvailabilityResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if !ussIDPattern.MatchString(req.UssId) {
		return nil, core.Fieldf("uss_id", "must match %s", ussIDPattern)
	}
	if req.Body == nil {
		return nil, &core.FieldError{Field: "body", Reason: "required"}
	}
	state := f3548.UssAvailabilityState(req.Body.Availability)
	if !state.Valid() {
		return nil, core.Fieldf("availability", "must be Unknown, Normal or Down")
	}
	reason := strings.TrimSpace(req.Body.Reason)
	if reason == "" || len(reason) > 500 {
		return nil, core.Fieldf("reason", "1 to 500 characters")
	}
	if s.DSS == "" || s.Tokens == nil {
		return nil, httpx.Refuse(http.StatusServiceUnavailable, SlugNoDSS, "no DSS or no client secret configured (DSS_BASE_URL, DP_CLIENT_SECRET_FILE)")
	}
	lock, acquired, err := s.DB.AdvisoryLock(ctx, pgstore.LockKey("dp_availability:"+req.UssId))
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, httpx.Refuse(http.StatusConflict, SlugArbitrationBusy, "an arbitration of this USS is in progress")
	}
	defer func() { _ = lock.Release(context.WithoutCancel(ctx)) }()
	record := func(event string, payload map[string]any) error {
		return s.DB.WithTx(context.WithoutCancel(ctx), func(q *pggen.Queries) error {
			_, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: "uss_availability", EntityID: req.UssId,
				EventType: event, Payload: payload})
			return err
		})
	}
	if err := record(EventAvailabilityRequested, map[string]any{"availability": string(state), "reason": reason}); err != nil {
		return nil, err
	}
	s.Counters.Inc(CounterArbitrations)
	res, err := s.arbitrate(ctx, req.UssId, state)
	if err != nil {
		s.Counters.Inc(CounterArbitrationsFailed)
		_ = record(EventAvailabilityFailed, map[string]any{"availability": string(state), "error": err.Error()})
		s.logger().Warn("USS availability arbitration failed", slog.String("uss_id", req.UssId), slog.String("error", err.Error()))
		return nil, httpx.Refuse(http.StatusBadGateway, SlugDSS, "the DSS did not take the arbitration: "+err.Error())
	}
	if err := record(EventAvailabilitySet, map[string]any{"availability": string(res.Status.Availability), "version": res.Version,
		"reason": reason}); err != nil {
		return nil, err
	}
	return gen.SetDPProviderAvailability200JSONResponse{UssId: req.UssId,
		Availability: gen.DPAvailabilityResultAvailability(res.Status.Availability), Version: res.Version}, nil
}

// arbitrate reads the USS's availability version at the DSS and sets
// the new state with it (F3548 read-modify-write).
func (s *Service) arbitrate(ctx context.Context, ussID string, state f3548.UssAvailabilityState) (*f3548.UssAvailabilityStatusResponse, error) {
	if _, err := dp.CheckBaseURL(s.DSS); err != nil {
		return nil, err
	}
	hc := s.HTTPClient
	if hc == nil {
		hc = dp.NoRedirectClient()
	}
	c, err := utmapi.NewClient(strings.TrimSuffix(s.DSS, "/"), utmapi.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	auth := func(ctx context.Context, req *http.Request) error {
		tok, err := s.Tokens.Token(ctx, s.DSS, ScopeArbitration)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := c.GetUssAvailability(ctx, ussID, auth)
	if err != nil {
		return nil, err
	}
	cur, err := readAvailability(resp)
	if err != nil {
		return nil, err
	}
	resp, err = c.SetUssAvailability(ctx, ussID, f3548.SetUssAvailabilityStatusParameters{Availability: state, OldVersion: cur.Version}, auth)
	if err != nil {
		return nil, err
	}
	return readAvailability(resp)
}

func readAvailability(resp *http.Response) (*f3548.UssAvailabilityStatusResponse, error) {
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDSSBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDSSBody {
		return nil, errors.New("DSS answer larger than the bound")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DSS answered HTTP %d", resp.StatusCode)
	}
	var r f3548.UssAvailabilityStatusResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, errors.New("DSS answer is not a UssAvailabilityStatusResponse")
	}
	return &r, nil
}
