package cisp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/cisp/cispclient"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// DefaultReconcileInterval is the mandatory reconciliation of every
// dataset, whether or not notifications arrive (spec 02 F3: 60 s).
const DefaultReconcileInterval = 60 * time.Second

// DefaultStaleBoundS is cis_stale_bound_s when no policy is loaded yet
// (the policy's version-1 default).
const DefaultStaleBoundS = 300

// sweepInterval is how often the expired delivery ids are deleted.
const sweepInterval = 10 * time.Minute

// Reader is the part of the CISP client the subscriber calls.
type Reader interface {
	VersionReader
	Head(ctx context.Context, ds Dataset, etag string) (Fetched, error)
	GetDataset(ctx context.Context, ds Dataset, sinceVersion *int64, etag string) (Fetched, error)
	GetURL(ctx context.Context, raw string) (Fetched, error)
	Subscribe(ctx context.Context, callback string, datasets []Dataset, bbox []float64) (cispclient.Subscription, error)
}

// Hint is what a notification says about a dataset.
type Hint struct {
	Version int64
	ETag    string
	// PullURL is set only when the receiver's guard accepted it (https
	// on the CISP's configured host and port).
	PullURL string
	Issuer  string
	At      time.Time
}

// SubscriberConfig configures a Subscriber.
type SubscriberConfig struct {
	// CISP is nil when CISP_BASE_URL is not configured: the subscriber
	// serves what the database holds, ageing, and says why.
	CISP       Reader
	Publishers PublisherVerifier
	Schemas    *Schemas
	Store      CacheStore
	Projector  Projector
	Announcer  Announcer
	Counters   *core.Counters
	Logger     *slog.Logger
	Limiter    *logging.Limiter
	// CallbackURL is CIS_CALLBACK_URL; empty means no push
	// subscription (the reconciliation alone).
	CallbackURL string
	BBox        []float64
	// ReconcileInterval is CIS_RECONCILE_S (60 s).
	ReconcileInterval time.Duration
	SubscribeRetry    time.Duration
	// SubscriptionRecheck is how often the push subscription is asked
	// of the CISP again once it is made (default five reconciliations).
	SubscriptionRecheck time.Duration
	// StaleBoundS is the policy's cis_stale_bound_s.
	StaleBoundS func() float64
	Now         func() time.Time
	// Direct is the ANSP's degraded direct path (direct.go).
	Direct DirectConfig
}

type dsState struct {
	cur       *Version
	kid       string
	fetchedAt time.Time
	checkedAt time.Time
	// empty is true when the CISP said the dataset has no version yet.
	empty   bool
	held    *UntrustedError
	refused *RefusalError
	lastErr string
	pending *Hint
	stale   bool
}

// Subscriber is the F3 subscriber: pulls on a notification, the 60 s
// reconciliation, the cache in cis_cache, the restrictions projection
// and its announcement.
type Subscriber struct {
	cfg SubscriberConfig

	locks map[Dataset]*sync.Mutex
	kick  map[Dataset]chan struct{}

	mu         sync.Mutex
	st         map[Dataset]*dsState
	hints      map[Dataset]*Hint
	subscribed string
	subStatus  string
	subErr     string
	warmErr    string

	// direct are the restrictions laid over the CISP's from the ANSP's
	// direct path, by identifier; directPending the notifications not
	// pulled yet, by restriction id (direct.go).
	direct        map[string]*directHeld
	directPending map[string]*DirectHint
	directKick    chan struct{}
}

// NewSubscriber builds a Subscriber.
func NewSubscriber(cfg SubscriberConfig) *Subscriber {
	if cfg.Counters == nil {
		cfg.Counters = &core.Counters{}
	}
	if cfg.Logger == nil {
		cfg.Logger = logging.Discard()
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = DefaultReconcileInterval
	}
	if cfg.SubscribeRetry <= 0 {
		cfg.SubscribeRetry = 30 * time.Second
	}
	if cfg.SubscriptionRecheck <= 0 {
		cfg.SubscriptionRecheck = 5 * cfg.ReconcileInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StaleBoundS == nil {
		cfg.StaleBoundS = func() float64 { return DefaultStaleBoundS }
	}
	s := &Subscriber{cfg: cfg, locks: map[Dataset]*sync.Mutex{}, kick: map[Dataset]chan struct{}{},
		st: map[Dataset]*dsState{}, hints: map[Dataset]*Hint{},
		direct: map[string]*directHeld{}, directPending: map[string]*DirectHint{}, directKick: make(chan struct{}, 1)}
	for _, d := range SubscribedDatasets {
		s.locks[d] = &sync.Mutex{}
		s.kick[d] = make(chan struct{}, 1)
		s.st[d] = &dsState{}
	}
	return s
}

// Counters are the subscriber's and the receiver's counters.
func (s *Subscriber) Counters() *core.Counters { return s.cfg.Counters }

// Run warms the cache from the database, subscribes, and pulls every
// dataset on a notification and every ReconcileInterval until ctx ends.
func (s *Subscriber) Run(ctx context.Context) {
	s.Warm(ctx)
	var wg sync.WaitGroup
	for _, d := range SubscribedDatasets {
		wg.Go(func() { s.worker(ctx, d) })
	}
	wg.Go(func() { s.subscribeLoop(ctx) })
	wg.Go(func() { s.sweepLoop(ctx) })
	wg.Go(func() { s.directWorker(ctx) })
	wg.Wait()
}

// Warm installs the versions cis_cache holds, with the age they have on
// the database clock, so a restart serves the last known datasets
// (stale if they are old) instead of none.
func (s *Subscriber) Warm(ctx context.Context) {
	s.warmDirect(ctx)
	s.mu.Lock()
	direct := len(s.direct) > 0
	s.mu.Unlock()
	restrictions := false
	defer func() {
		if direct && !restrictions {
			// Only the direct path holds restrictions: they are
			// projected (and announced) without a CISP version.
			s.reproject(ctx)
		}
	}()
	if s.cfg.Store == nil {
		return
	}
	stored, err := s.cfg.Store.Load(ctx)
	if err != nil {
		s.mu.Lock()
		s.warmErr = short(err.Error())
		s.mu.Unlock()
		logging.Error(ctx, s.cfg.Logger, "the CIS cache could not be read from the database", err)
		return
	}
	now := s.cfg.Now()
	for i := range stored {
		c := &stored[i]
		v, rf := ParseVersion(s.cfg.Schemas, c.Dataset, c.Payload, c.ETag, c.Version)
		if rf != nil {
			s.cfg.Logger.Error("a stored CIS version no longer parses; it is pulled again", slog.String("dataset", string(c.Dataset)),
				slog.Int64("version", c.Version), slog.String("problem", rf.First))
			continue
		}
		v.UpdatedAt = c.UpdatedAt
		age := time.Duration(math.Max(0, c.AgeS) * float64(time.Second))
		s.mu.Lock()
		st := s.st[c.Dataset]
		if st != nil {
			st.cur, st.kid, st.fetchedAt, st.checkedAt = v, c.PublisherKID, c.FetchedAt, now.Add(-age)
		}
		s.mu.Unlock()
		s.cfg.Logger.Info("CIS version loaded from the database", slog.String("dataset", string(c.Dataset)),
			slog.Int64("cis_version", c.Version), slog.Float64("cis_age_s", c.AgeS))
		if c.Dataset == DatasetRestrictions {
			restrictions = true
			s.project(ctx, v)
		}
	}
}

// Trigger asks for a pull of d after a notification; it never blocks.
// The newest hint wins.
func (s *Subscriber) Trigger(d Dataset, h Hint) {
	s.mu.Lock()
	if old := s.hints[d]; old == nil || h.Version >= old.Version {
		s.hints[d] = &h
	}
	if st := s.st[d]; st != nil && (st.pending == nil || h.Version > st.pending.Version) {
		hc := h
		st.pending = &hc
	}
	s.mu.Unlock()
	select {
	case s.kick[d] <- struct{}{}:
	default:
	}
}

func (s *Subscriber) worker(ctx context.Context, d Dataset) {
	t := time.NewTicker(s.cfg.ReconcileInterval)
	defer t.Stop()
	_ = s.Pull(ctx, d, nil)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick[d]:
			s.mu.Lock()
			h := s.hints[d]
			delete(s.hints, d)
			s.mu.Unlock()
			_ = s.Pull(ctx, d, h)
		case <-t.C:
			_ = s.Pull(ctx, d, nil)
		}
		s.checkStale(ctx)
	}
}

// Pull reads d from the CISP and installs a newer version. h is the
// notification that asked for it; nil is the reconciliation, which asks
// HEAD with the held ETag first and reads only on a change. A version at
// or below the one held, named by h, is not pulled (a replay, counted).
// With a version held, an ED-318 dataset is read as the delta from it
// (h.PullURL when the receiver accepted it, else ?since_version= on the
// configured CISP); any trouble with the delta reads the dataset whole.
func (s *Subscriber) Pull(ctx context.Context, d Dataset, h *Hint) error {
	if s.cfg.CISP == nil {
		return s.failPull(d, errors.New("no CISP is configured (CISP_BASE_URL)"))
	}
	lock := s.locks[d]
	lock.Lock()
	defer lock.Unlock()
	s.mu.Lock()
	cur := s.st[d].cur
	s.mu.Unlock()
	if h != nil && h.Version > 0 && cur != nil && h.Version <= cur.Number {
		s.cfg.Counters.Inc(CounterVersionReplays)
		s.clearPending(d, cur.Number)
		return nil
	}
	reconcile := h == nil
	if reconcile && cur != nil {
		s.cfg.Counters.Inc(CounterHeads)
		f, err := s.cfg.CISP.Head(ctx, d, cur.ETag)
		if err != nil {
			return s.failPull(d, err)
		}
		if f.Status == http.StatusNotModified || (f.Status == http.StatusOK && f.ETag == cur.ETag) {
			s.cfg.Counters.Inc(CounterNotModified)
			s.confirm(ctx, d, cur)
			return nil
		}
	}
	s.cfg.Counters.Inc(CounterPulls)
	if cur != nil && d.ED318() {
		if v, ok := s.pullDelta(ctx, d, cur, h); ok {
			return s.accept(ctx, v, cur, reconcile)
		}
	}
	etag := ""
	if cur != nil {
		etag = cur.ETag
	}
	f, err := s.cfg.CISP.GetDataset(ctx, d, nil, etag)
	if err != nil {
		return s.failPull(d, err)
	}
	switch f.Status {
	case http.StatusNotModified:
		s.cfg.Counters.Inc(CounterNotModified)
		s.confirm(ctx, d, cur)
		return nil
	case http.StatusNotFound:
		s.confirmEmpty(ctx, d)
		return nil
	}
	v, rf := ParseVersion(s.cfg.Schemas, d, f.Body, f.ETag, f.Version)
	if rf != nil {
		return s.refuse(d, rf)
	}
	return s.accept(ctx, v, cur, reconcile)
}

func (s *Subscriber) pullDelta(ctx context.Context, d Dataset, cur *Version, h *Hint) (*Version, bool) {
	var f Fetched
	var err error
	if h != nil && h.PullURL != "" {
		f, err = s.cfg.CISP.GetURL(ctx, h.PullURL)
	} else {
		since := cur.Number
		f, err = s.cfg.CISP.GetDataset(ctx, d, &since, "")
	}
	if err == nil && f.Status != http.StatusOK {
		err = fmt.Errorf("the delta answered %d", f.Status)
	}
	if err != nil {
		s.cfg.Counters.Inc(CounterDeltaUnusable)
		s.cfg.Logger.Warn("CIS delta not read; reading the dataset whole", slog.String("dataset", string(d)),
			slog.String("error", short(err.Error())))
		return nil, false
	}
	body, to, err := mergeDelta(cur, f.Body)
	if err != nil {
		s.cfg.Counters.Inc(CounterDeltaUnusable)
		s.cfg.Logger.Warn("CIS delta not applied; reading the dataset whole", slog.String("dataset", string(d)),
			slog.String("error", short(err.Error())))
		return nil, false
	}
	v, rf := ParseVersion(s.cfg.Schemas, d, body, "", to)
	if rf != nil {
		// Read it whole, so that a refusal names the CISP's bytes.
		s.cfg.Counters.Inc(CounterDeltaUnusable)
		return nil, false
	}
	v.Delta = true
	s.cfg.Counters.Inc(CounterDeltaPulls)
	return v, true
}

// accept installs v when it is newer than cur and its publisher's
// signature verifies; a version whose signature is missing or does not
// verify is held (never used) and cur stays.
func (s *Subscriber) accept(ctx context.Context, v, cur *Version, reconcile bool) error {
	if cur != nil && v.Number <= cur.Number {
		if v.Number < cur.Number {
			s.cfg.Counters.Inc(CounterVersionReplays)
		}
		s.confirm(ctx, v.Dataset, cur)
		return nil
	}
	kid, err := checkProvenance(ctx, s.cfg.CISP, s.cfg.Publishers, v)
	if err != nil {
		var ue *UntrustedError
		if errors.As(err, &ue) {
			if ue.Mismatch {
				s.cfg.Counters.Inc(CounterSignedMismatch)
			}
			return s.hold(v, ue)
		}
		return s.failPull(v.Dataset, err)
	}
	now := s.cfg.Now()
	s.mu.Lock()
	st := s.st[v.Dataset]
	st.cur, st.kid, st.fetchedAt, st.checkedAt, st.empty = v, kid, now, now, false
	st.refused, st.lastErr = nil, ""
	if st.held != nil && st.held.Version <= v.Number {
		st.held = nil
	}
	if st.pending != nil && st.pending.Version <= v.Number {
		st.pending = nil
	}
	s.mu.Unlock()
	if reconcile && cur != nil {
		s.cfg.Counters.Inc(CounterReconcileCatchups)
	}
	s.cfg.Logger.Info("CIS version installed", slog.String("dataset", string(v.Dataset)), slog.Int64("cis_version", v.Number),
		slog.Int("features", v.FeatureCount()), slog.Bool("delta", v.Delta), slog.Bool("reconcile", reconcile),
		slog.String("publisher_kid", kid))
	c := &Cached{
		Dataset: v.Dataset, Version: v.Number, ETag: v.ETag, UpdatedAt: v.UpdatedAt, FetchedAt: now, CheckedAt: now,
		FeatureCount: v.FeatureCount(), PublisherKID: kid, Payload: v.Body,
	}
	if s.cfg.Store != nil {
		if err := s.cfg.Store.Save(ctx, c); err != nil {
			s.cfg.Counters.Inc(CounterStoreFailed)
			logging.Error(ctx, s.cfg.Logger, "CIS version not stored; it is served from memory", err,
				slog.String("dataset", string(v.Dataset)), slog.Int64("cis_version", v.Number))
		}
	}
	if v.Dataset == DatasetRestrictions {
		s.project(ctx, v)
	}
	s.announce(ctx, c)
	if v.Dataset == DatasetRestrictions && s.dropDirect(ctx) {
		// The CISP now holds what came directly: the overlay is gone.
		s.reproject(ctx)
	}
	return nil
}

func (s *Subscriber) project(ctx context.Context, v *Version) {
	if s.cfg.Projector == nil {
		return
	}
	var rows []RestrictionRow
	version, etag := int64(0), ETagOf(DatasetRestrictions, 0)
	rows = s.mergedRows(v)
	if v != nil {
		version, etag = v.Number, v.ETag
	}
	err := s.cfg.Projector.ProjectRestrictions(ctx, version, etag, rows, s.cfg.Now().UTC())
	switch {
	case errors.Is(err, ErrProjectionNewer):
		s.cfg.Counters.Inc(CounterProjectionOlder)
	case err != nil:
		s.cfg.Counters.Inc(CounterProjectionFailed)
		s.setErr(DatasetRestrictions, "projection: "+short(err.Error()))
		logging.Error(ctx, s.cfg.Logger, "restrictions projection not written; the detectors keep the previous one", err,
			slog.Int64("cis_version", version))
	}
}

func (s *Subscriber) announce(ctx context.Context, c *Cached) {
	if s.cfg.Announcer == nil {
		return
	}
	if err := s.cfg.Announcer.Announce(ctx, c); err != nil {
		s.cfg.Counters.Inc(CounterAnnounceFailed)
		s.cfg.Logger.Warn("CIS version not announced on the bus; readers catch up on their re-read",
			slog.String("dataset", string(c.Dataset)), slog.String("error", short(err.Error())))
	}
}

// confirm records that the CISP confirmed the version held.
func (s *Subscriber) confirm(ctx context.Context, d Dataset, cur *Version) {
	s.mu.Lock()
	st := s.st[d]
	st.checkedAt, st.lastErr = s.cfg.Now(), ""
	s.mu.Unlock()
	if cur == nil {
		return
	}
	s.clearPending(d, cur.Number)
	if s.cfg.Store != nil {
		if err := s.cfg.Store.Touch(ctx, d, cur.Number); err != nil {
			s.cfg.Counters.Inc(CounterStoreFailed)
			s.cfg.Logger.Warn("CIS confirmation not stored", slog.String("dataset", string(d)), slog.String("error", short(err.Error())))
		}
	}
}

// confirmEmpty records that the CISP holds no version of d yet: a known
// empty dataset, not an unknown one. The restrictions projection says so
// (version 0, no rows), so the detectors tell "no restriction" from
// "never projected".
func (s *Subscriber) confirmEmpty(ctx context.Context, d Dataset) {
	s.mu.Lock()
	st := s.st[d]
	first := !st.empty
	st.empty, st.checkedAt, st.lastErr = st.cur == nil, s.cfg.Now(), ""
	empty := st.empty
	s.mu.Unlock()
	if empty && first && d == DatasetRestrictions {
		s.project(ctx, nil)
	}
}

func (s *Subscriber) hold(v *Version, ue *UntrustedError) error {
	s.cfg.Counters.Inc(CounterUntrusted)
	s.mu.Lock()
	st := s.st[v.Dataset]
	prev := st.held
	st.held, st.lastErr = ue, ""
	if st.pending != nil && st.pending.Version <= v.Number {
		st.pending = nil
	}
	s.mu.Unlock()
	if prev == nil || prev.Version != ue.Version || prev.Reason != ue.Reason {
		s.cfg.Logger.Error("CIS version held: its publisher's signature does not cover it; the previous version is kept",
			slog.String("dataset", string(v.Dataset)), slog.Int64("cis_version", v.Number), slog.String("reason", ue.Reason))
	}
	return ue
}

func (s *Subscriber) refuse(d Dataset, rf *RefusalError) error {
	s.cfg.Counters.Inc(CounterRejectedPublication)
	s.mu.Lock()
	st := s.st[d]
	prev := st.refused
	st.refused, st.lastErr = rf, ""
	s.mu.Unlock()
	if prev == nil || prev.Version != rf.Version {
		s.cfg.Logger.Error("CIS publication refused whole; the previous version is kept", slog.String("dataset", string(d)),
			slog.Int64("cis_version", rf.Version), slog.String("problem", rf.First), slog.Int("problems", rf.Problems))
	}
	return rf
}

func (s *Subscriber) failPull(d Dataset, err error) error {
	s.cfg.Counters.Inc(CounterPullFailed)
	s.setErr(d, short(err.Error()))
	l := s.cfg.Logger
	if s.cfg.Limiter != nil {
		l = s.cfg.Limiter.Limited("cisp-pull-" + string(d))
	}
	l.Warn("CIS pull failed; the version held is served, ageing", slog.String("dataset", string(d)), slog.String("error", short(err.Error())))
	return err
}

func (s *Subscriber) setErr(d Dataset, e string) {
	s.mu.Lock()
	s.st[d].lastErr = e
	s.mu.Unlock()
}

func (s *Subscriber) clearPending(d Dataset, held int64) {
	s.mu.Lock()
	if st := s.st[d]; st.pending != nil && st.pending.Version <= held {
		st.pending = nil
	}
	s.mu.Unlock()
}

// checkStale logs every dataset's move into and out of cis_stale once
// (the console shows it on every frame; the log says when).
func (s *Subscriber) checkStale(ctx context.Context) {
	now := s.cfg.Now()
	bound := s.cfg.StaleBoundS()
	type change struct {
		d     Dataset
		stale bool
		age   float64
	}
	var changes []change
	s.mu.Lock()
	for _, d := range SubscribedDatasets {
		st := s.st[d]
		age, ok := st.age(now)
		stale := !ok || age > bound
		if stale != st.stale {
			st.stale = stale
			changes = append(changes, change{d, stale, age})
		}
	}
	s.mu.Unlock()
	for _, c := range changes {
		if c.stale {
			s.cfg.Counters.Inc(CounterStaleTransitions)
			s.cfg.Logger.ErrorContext(ctx, "CIS dataset stale: the console shows cis_stale", slog.String("dataset", string(c.d)),
				slog.Float64("cis_age_s", c.age), slog.Float64("cis_stale_bound_s", bound))
		} else {
			s.cfg.Logger.InfoContext(ctx, "CIS dataset fresh again", slog.String("dataset", string(c.d)), slog.Float64("cis_age_s", c.age))
		}
	}
}

// age is the time since the CISP last confirmed the dataset; false when
// it never did (nothing held and no answer yet).
func (st *dsState) age(now time.Time) (float64, bool) {
	if st.checkedAt.IsZero() || (st.cur == nil && !st.empty) {
		return 0, false
	}
	return math.Max(0, now.Sub(st.checkedAt).Seconds()), true
}

// subscribeLoop makes the push subscription and asks for it again every
// SubscriptionRecheck (Subscribe is idempotent): a subscription the
// CISP lost (a restore, a delete) is made again, and the status shown is
// the one the CISP answered last, never the one of start-up (audit
// A-S3).
func (s *Subscriber) subscribeLoop(ctx context.Context) {
	if s.cfg.CISP == nil || s.cfg.CallbackURL == "" {
		return
	}
	for {
		sub, err := s.cfg.CISP.Subscribe(ctx, s.cfg.CallbackURL, SubscribedDatasets, s.cfg.BBox)
		if err != nil && ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		prevID, prevStatus := s.subscribed, s.subStatus
		if err == nil {
			s.subscribed, s.subStatus, s.subErr = sub.Id, string(sub.Status), ""
		} else {
			s.subErr = short(err.Error())
		}
		s.mu.Unlock()
		wait := s.cfg.SubscribeRetry
		switch {
		case err != nil:
			s.cfg.Counters.Inc(CounterSubscribeFailed)
			s.cfg.Logger.Warn("CISP subscription failed; the reconciliation alone keeps the cache", slog.String("error", short(err.Error())))
		case prevID == "":
			wait = s.cfg.SubscriptionRecheck
			s.cfg.Logger.Info("subscribed to the CISP's change notifications", slog.String("subscription", sub.Id),
				slog.String("status", string(sub.Status)))
		default:
			wait = s.cfg.SubscriptionRecheck
			s.cfg.Counters.Inc(CounterSubscriptionRechecks)
			if sub.Id != prevID || string(sub.Status) != prevStatus {
				s.cfg.Counters.Inc(CounterSubscriptionChanged)
				s.cfg.Logger.Warn("the CISP's subscription changed since it was last checked; it is the one shown now",
					slog.String("subscription", sub.Id), slog.String("was", prevID), slog.String("status", string(sub.Status)),
					slog.String("was_status", prevStatus))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (s *Subscriber) sweepLoop(ctx context.Context) {
	if s.cfg.Store == nil {
		return
	}
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.cfg.Store.SweepJTIs(ctx); err != nil {
				s.cfg.Logger.Warn("expired CIS delivery ids not swept", slog.String("error", short(err.Error())))
			}
		}
	}
}

// CacheState is one dataset's state for the console and the status line.
type CacheState struct {
	Dataset        Dataset
	Version        *int64
	ETag           string
	UpdatedAt      *time.Time
	FetchedAt      *time.Time
	CheckedAt      *time.Time
	AgeS           *float64
	Stale          bool
	FeatureCount   *int
	HeldVersion    *int64
	HeldReason     string
	RefusedVersion *int64
	RefusedReason  string
	LastError      string
	// Pending is a notified version not pulled yet.
	Pending *int64
}

// State is every subscribed dataset's state at now.
func (s *Subscriber) State() []CacheState {
	now := s.cfg.Now()
	bound := s.cfg.StaleBoundS()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]CacheState, 0, len(SubscribedDatasets))
	for _, d := range SubscribedDatasets {
		st := s.st[d]
		cs := CacheState{Dataset: d, LastError: st.lastErr}
		if st.lastErr == "" && st.cur == nil && s.warmErr != "" {
			cs.LastError = "cache not read: " + s.warmErr
		}
		if st.cur != nil {
			v, n := st.cur.Number, st.cur.FeatureCount()
			cs.Version, cs.ETag, cs.UpdatedAt, cs.FeatureCount = &v, st.cur.ETag, st.cur.UpdatedAt, &n
			if !st.fetchedAt.IsZero() {
				f := st.fetchedAt
				cs.FetchedAt = &f
			}
		} else if st.empty {
			v, n := int64(0), 0
			cs.Version, cs.FeatureCount = &v, &n
		}
		if !st.checkedAt.IsZero() {
			c := st.checkedAt
			cs.CheckedAt = &c
		}
		age, ok := st.age(now)
		if ok {
			cs.AgeS = &age
		}
		cs.Stale = !ok || age > bound
		if st.held != nil {
			v := st.held.Version
			cs.HeldVersion, cs.HeldReason = &v, st.held.Reason
		}
		if st.refused != nil {
			v := st.refused.Version
			cs.RefusedVersion, cs.RefusedReason = &v, st.refused.First
		}
		if st.pending != nil {
			v := st.pending.Version
			cs.Pending = &v
		}
		out = append(out, cs)
	}
	return out
}

// SubscriptionState is the push subscription's state.
type SubscriptionState struct {
	Enabled     bool
	CallbackURL string
	ID          string
	Status      string
	LastError   string
}

// Subscription is the push subscription's state.
func (s *Subscriber) Subscription() SubscriptionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SubscriptionState{Enabled: s.cfg.CallbackURL != "" && s.cfg.CISP != nil, CallbackURL: s.cfg.CallbackURL,
		ID: s.subscribed, Status: s.subStatus, LastError: s.subErr}
}

// Current is the version held of d, or nil.
func (s *Subscriber) Current(d Dataset) *Version {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.st[d]; st != nil {
		return st.cur
	}
	return nil
}
