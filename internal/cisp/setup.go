package cisp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// NotifyIssuer is one allow-listed issuer of POST /v1/cis/notifications
// (AUTHORITY_CIS_NOTIFY_ISSUERS).
type NotifyIssuer struct {
	Issuer string
	// JWKSURL is the issuer's JWKS; Keys, when set, is used instead
	// (tests and static deployments).
	JWKSURL string
	Keys    *coreauth.IssuerConfig
	// ANSP is true for the ANSP's direct delivery (M5).
	ANSP bool
}

// Setup is what Assemble needs from the process.
type Setup struct {
	DB        *pg.DB
	Audit     *audit.Writer
	Projector *ts.Projector
	// JS announces on cis.v1.<dataset>; nil announces nothing.
	JS          jetstream.JetStream
	NATSTimeout time.Duration
	// PublicationRing is this system's publication key (M26; nil when
	// PUBLICATION_KEY_FILE is not configured: every publication is
	// refused). It signs, and its JWKS verifies the authority's own
	// versions read back from the CISP.
	PublicationRing *coreauth.KeyRing
	// Tokens hands out the authority-01 tokens for the CISP.
	Tokens TokenSource
	// BaseURL is CISP_BASE_URL; empty disables everything that calls
	// the CISP (said on the status line and the console).
	BaseURL     string
	CallbackURL string
	BBox        []float64
	// Audiences are this system's hosts (AUTHORITY_AUDIENCES, M19).
	Audiences []string
	// NotifyIssuers is AUTHORITY_CIS_NOTIFY_ISSUERS.
	NotifyIssuers []NotifyIssuer
	// ANSPPublisherJWKSURL verifies the publisher signatures of pulled
	// restrictions versions (CIS_ANSP_PUBLISHER_JWKS_URL).
	ANSPPublisherJWKSURL string
	// PublisherKeys, when set, replace the publication ring's JWKS and
	// ANSPPublisherJWKSURL by publisher (tests).
	PublisherKeys      map[string]coreauth.IssuerConfig
	PublisherSigMaxAge time.Duration

	ReconcileInterval time.Duration
	// DirectMax and DirectKeep bound the ANSP's degraded direct path
	// (CIS_DIRECT_MAX, CIS_DIRECT_KEEP_S); DirectClient pulls its
	// pull_url (nil: a plain client bounded by DefaultDirectTimeout).
	DirectMax         int
	DirectKeep        time.Duration
	DirectClient      *http.Client
	HeartbeatInterval time.Duration
	SendPoll          time.Duration
	BackoffMin        time.Duration
	BackoffMax        time.Duration
	GiveUp            time.Duration
	MaxLiveJTIs       int64
	StaleBoundS       func() float64

	// HTTPClient calls the CISP and fetches JWKS (nil: the defaults).
	HTTPClient *http.Client
	Logger     *slog.Logger
	Limiter    *logging.Limiter
	Now        func() time.Time
}

// Parts is the assembled CISP client.
type Parts struct {
	Configured bool
	Client     *Client
	Schemas    *Schemas
	Outbox     *Outbox
	Sender     *Sender
	Heartbeat  *Heartbeat
	Subscriber *Subscriber
	Receiver   *Receiver
	Handler    Handler
	Publishers *Publishers
	Notify     *LazyCompactVerifier
	Counters   *core.Counters

	sendPoll time.Duration
}

// Lock keys of the jobs (pg.LockKey).
const (
	lockSender    = "cisp/sender"
	lockHeartbeat = "cisp/heartbeat"
)

// Assemble builds the CISP client on the relational database, the
// projection pool and the bus. Without BaseURL the outbox still
// validates, signs and queues (the ages grow on the console) and the
// receiver still verifies, but nothing is sent or pulled.
func Assemble(_ context.Context, s Setup) (*Parts, error) {
	schemas, err := LoadSchemas()
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	logger := s.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	store := PG{DB: s.DB, Audit: s.Audit}
	p := &Parts{Schemas: schemas, Counters: counters, sendPoll: s.SendPoll}
	var signer Signer
	keys := map[string]coreauth.IssuerConfig{}
	if s.PublicationRing != nil {
		signer = s.PublicationRing
		keys[PublisherAuthority] = coreauth.IssuerConfig{Keys: s.PublicationRing.JWKS()}
	}
	if s.ANSPPublisherJWKSURL != "" {
		keys[PublisherANSP] = coreauth.IssuerConfig{JWKSURL: s.ANSPPublisherJWKSURL}
	}
	for name, k := range s.PublisherKeys {
		keys[name] = k
	}
	p.Outbox = NewOutbox(schemas, signer, store, counters)
	if s.Now != nil {
		p.Outbox.Now = s.Now
	}
	if s.BaseURL != "" {
		p.Client, err = NewClient(ClientConfig{BaseURL: s.BaseURL, Tokens: s.Tokens, HTTPClient: s.HTTPClient})
		if err != nil {
			return nil, err
		}
		p.Configured = true
	}
	p.Publishers = NewPublishers(keys, s.PublisherSigMaxAge, s.HTTPClient)
	var projector Projector
	if s.Projector != nil {
		projector = TSProjector{P: s.Projector}
	}
	var announcer Announcer
	if s.JS != nil {
		announcer = &BusAnnouncer{JS: s.JS, Producer: "uspace-authority/api", Timeout: orDefault(s.NATSTimeout, 2*time.Second), Now: s.Now}
	}
	var reader Reader
	if p.Client != nil {
		reader = p.Client
	}
	p.Subscriber = NewSubscriber(SubscriberConfig{
		CISP: reader, Publishers: p.Publishers, Schemas: schemas, Store: store, Projector: projector, Announcer: announcer,
		Counters: counters, Logger: logger, Limiter: s.Limiter, CallbackURL: s.CallbackURL, BBox: s.BBox,
		ReconcileInterval: s.ReconcileInterval, StaleBoundS: s.StaleBoundS, Now: s.Now,
		// The ANSP's pull_url is public and signed: a client of its own,
		// never the CISP's.
		Direct: DirectConfig{Client: orClient(s.DirectClient), Store: directStore(s.DB, store), Max: s.DirectMax, Keep: s.DirectKeep},
	})
	if p.Client != nil {
		p.Sender = &Sender{
			Store: store, CISP: p.Client, Signer: signer, Lock: dbLock(s.DB, lockSender), Counters: counters, Logger: logger,
			Now: s.Now, BackoffMin: s.BackoffMin, BackoffMax: s.BackoffMax, GiveUp: s.GiveUp,
		}
		p.Heartbeat = &Heartbeat{CISP: p.Client, Lock: dbLock(s.DB, lockHeartbeat), Interval: s.HeartbeatInterval,
			Counters: counters, Logger: logger, Limiter: s.Limiter, Now: s.Now}
	}
	issuers := map[string]coreauth.IssuerConfig{}
	senders := map[string]NotifySender{}
	for _, ni := range s.NotifyIssuers {
		k := coreauth.IssuerConfig{JWKSURL: ni.JWKSURL}
		if ni.Keys != nil {
			k = *ni.Keys
		}
		issuers[ni.Issuer] = k
		senders[ni.Issuer] = NotifySender{ANSP: ni.ANSP, BaseURL: ni.Issuer}
	}
	p.Notify = NewLazyCompactVerifier(coreauth.CompactConfig{Issuers: issuers, Audiences: s.Audiences, HTTPClient: s.HTTPClient, Now: s.Now})
	var guard PullURLChecker
	if p.Client != nil {
		guard = p.Client
	}
	p.Receiver = NewReceiver(ReceiverConfig{
		Verifier: p.Notify, Senders: senders, Store: store, PullURL: guard, Trigger: p.Subscriber.Trigger, TriggerDirect: p.Subscriber.TriggerDirect,
		MaxLiveJTIs: s.MaxLiveJTIs, Counters: counters, Logger: logger, Limiter: s.Limiter, Now: s.Now,
	})
	p.Handler = Handler{Store: store, Subscriber: p.Subscriber, Heartbeat: p.Heartbeat, Configured: p.Configured}
	return p, nil
}

// orClient is c, or a plain client bounded by DefaultDirectTimeout.
func orClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: DefaultDirectTimeout}
}

// directStore is the relational store of the direct restrictions, nil
// without a database (memory only).
func directStore(db *pg.DB, store PG) DirectStore {
	if db == nil {
		return nil
	}
	return store
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

// dbLock is the job's session advisory lock on the relational database.
func dbLock(db *pg.DB, name string) Locker {
	if db == nil {
		return NoLock
	}
	key := pg.LockKey(name)
	return func(ctx context.Context) (func(), bool, error) {
		l, ok, err := db.AdvisoryLock(ctx, key)
		if err != nil || !ok {
			return func() {}, ok, err
		}
		return func() { _ = l.Release(context.WithoutCancel(ctx)) }, true, nil
	}
}

// Run runs the sender, the heartbeat, the subscriber and the key
// fetches until ctx ends.
func (p *Parts) Run(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Go(func() { p.Publishers.Run(ctx) })
	wg.Go(func() { p.Notify.Run(ctx) })
	wg.Go(func() { p.Subscriber.Run(ctx) })
	if p.Sender != nil {
		wg.Go(func() { p.Sender.Run(ctx, p.Outbox.Woken(), p.sendPoll, nil) })
	}
	if p.Heartbeat != nil {
		wg.Go(func() { p.Heartbeat.Run(ctx) })
	}
	wg.Wait()
}

// StatusAttrs are the CISP client's entries on the status line (E-09):
// whether a CISP is configured, every dataset's cis_version and
// cis_age_s, the stale ones, the outbox's not-yet-published ages, the
// heartbeat's last answer, the publisher keys not fetched.
func (p *Parts) StatusAttrs() []slog.Attr {
	attrs := []slog.Attr{slog.Bool("cisp_configured", p.Configured)}
	var stale []string
	states := p.Subscriber.State()
	for i := range states {
		c := &states[i]
		if c.Version != nil {
			attrs = append(attrs, slog.Int64("cis_"+string(c.Dataset)+"_version", *c.Version))
		}
		if c.AgeS != nil {
			attrs = append(attrs, slog.Float64("cis_"+string(c.Dataset)+"_age_s", *c.AgeS))
		}
		if c.Stale {
			stale = append(stale, string(c.Dataset))
		}
	}
	attrs = append(attrs, slog.String("cis_stale", strings.Join(stale, ",")))
	if p.Sender != nil {
		ages := p.Sender.PendingAges(time.Now())
		names := make([]string, 0, len(ages))
		for d := range ages {
			names = append(names, string(d))
		}
		sort.Strings(names)
		for _, d := range names {
			attrs = append(attrs, slog.Float64("publication_"+d+"_pending_age_s", ages[Dataset(d)]))
		}
	}
	if p.Heartbeat != nil {
		hb := p.Heartbeat.State()
		attrs = append(attrs, slog.Int("cis_heartbeat_failures", hb.ConsecutiveFailures))
		if hb.LastSuccessAt != nil {
			attrs = append(attrs, slog.Float64("cis_heartbeat_age_s", time.Since(*hb.LastSuccessAt).Seconds()))
		}
	}
	if m := p.Publishers.Missing(); len(m) > 0 {
		attrs = append(attrs, slog.String("cis_publisher_keys_missing", strings.Join(m, "; ")))
	}
	if e := p.Notify.LastError(); e != "" {
		attrs = append(attrs, slog.String("cis_notify_keys", e))
	}
	return attrs
}

// LazyCompactVerifier is the receiver's verifier, built when the
// issuers' JWKS can be fetched: until then every notification is
// refused 401 (the CISP retries it) and the status line says why. An
// empty allow-list refuses everything.
type LazyCompactVerifier struct {
	cfg   coreauth.CompactConfig
	retry time.Duration
	v     atomic.Pointer[coreauth.CompactVerifier]

	mu      sync.Mutex
	lastErr string
}

// NewLazyCompactVerifier returns a verifier that Run builds.
func NewLazyCompactVerifier(cfg coreauth.CompactConfig) *LazyCompactVerifier {
	return &LazyCompactVerifier{cfg: cfg, retry: DefaultKeysRetry}
}

// errNoNotifyIssuers refuses every notification of a receiver with no
// allow-listed issuer.
var errNoNotifyIssuers = errors.New("no notification issuers are configured (AUTHORITY_CIS_NOTIFY_ISSUERS)")

// Build tries once to build the verifier.
func (l *LazyCompactVerifier) Build(ctx context.Context) error {
	if l.v.Load() != nil {
		return nil
	}
	if len(l.cfg.Issuers) == 0 {
		l.setErr(errNoNotifyIssuers.Error())
		return errNoNotifyIssuers
	}
	v, err := coreauth.NewCompactVerifier(ctx, l.cfg)
	if err != nil {
		l.setErr("the notification issuers' keys are not fetched: " + short(err.Error()))
		return err
	}
	l.setErr("")
	l.v.Store(v)
	return nil
}

func (l *LazyCompactVerifier) setErr(e string) {
	l.mu.Lock()
	l.lastErr = e
	l.mu.Unlock()
}

// LastError is why the verifier is not built ("" once it is).
func (l *LazyCompactVerifier) LastError() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastErr
}

// Run builds the verifier, trying again every retry period until it is
// built, the allow-list is empty, or ctx ends.
func (l *LazyCompactVerifier) Run(ctx context.Context) {
	t := time.NewTicker(l.retry)
	defer t.Stop()
	for {
		err := l.Build(ctx)
		if err == nil || errors.Is(err, errNoNotifyIssuers) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Verify verifies with the built verifier, or refuses.
func (l *LazyCompactVerifier) Verify(ctx context.Context, token string) (coreauth.CompactClaims, json.RawMessage, error) {
	if v := l.v.Load(); v != nil {
		return v.Verify(ctx, token)
	}
	why := l.LastError()
	if why == "" {
		why = "the notification issuers' keys are not fetched yet"
	}
	return coreauth.CompactClaims{}, nil, &coreauth.TokenError{Counter: coreauth.CounterRejectedIssuer, Claim: "iss", Reason: why}
}

// Counters are core's verifier counters once built, empty before.
func (l *LazyCompactVerifier) Counters() *core.Counters {
	if v := l.v.Load(); v != nil {
		return v.Counters()
	}
	return &core.Counters{}
}
