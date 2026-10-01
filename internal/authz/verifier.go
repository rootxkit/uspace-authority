package authz

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Counters of the verifier besides core's verdict counters.
const (
	CounterIssuerUnavailable = "rejected_issuer_unavailable" // a token of a configured peer whose JWKS was never fetched
	CounterPeerFetchFailed   = "peer_jwks_unavailable"       // a peer's first JWKS fetch failed; retried
	CounterSelfRebuildFailed = "self_keys_rebuild_failed"    // this issuer's own key set could not be rebuilt
)

// Peer is an allow-listed issuer other than this one: a JWKS URL, or
// static keys (tests, the vectors).
type Peer struct {
	JWKSURL string
	Keys    jwk.Set
}

// VerifierConfig is the verification wiring of WP-2: core/auth.Config
// with this system's audiences (AUTHORITY_AUDIENCES), this issuer and
// the configured peers (the CISP, the ANSP, the lab).
type VerifierConfig struct {
	// SelfIssuer is this issuer's iss; SelfKeys its token keys at a
	// moment (tokens.Keys.TokenKeys: the publication key is never one).
	SelfIssuer string
	SelfKeys   func(now time.Time) (jwk.Set, error)
	Audiences  []string
	Peers      map[string]Peer
	// MaxSkew zero is core's default (30 s).
	MaxSkew    time.Duration
	HTTPClient *http.Client
	Now        func() time.Time
	Logger     *slog.Logger
	// RetryEvery is the wait between attempts at a peer whose JWKS could
	// not be fetched at start (default 30 s).
	RetryEvery time.Duration
}

// Verifier verifies every token this system accepts with core's
// Verifier, RS256 only, StrictSessionClaims on. This issuer's own keys
// are a static set rebuilt when the signing keys change (Rebuild); each
// peer has its own core Verifier fetching its JWKS, built in the
// background when its issuer is unreachable at start, so one absent
// peer neither stops the process nor hides the others (B-08). A token
// is routed by its unverified iss to the verifier allowing exactly that
// issuer, which then judges every claim, iss included; an unknown iss
// reaches this issuer's verifier and is refused there as
// rejected_issuer. Counters aggregates the verdicts by core's counter
// names.
type Verifier struct {
	cfg      VerifierConfig
	self     atomic.Pointer[auth.Verifier]
	counters core.Counters

	mu    sync.RWMutex
	peers map[string]*auth.Verifier
}

func (c *VerifierConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// NewVerifier builds the wiring. A peer whose JWKS cannot be fetched is
// left unready and retried by Run; this issuer's own set must build.
func NewVerifier(ctx context.Context, c VerifierConfig) (*Verifier, error) {
	if c.SelfIssuer == "" || c.SelfKeys == nil {
		return nil, core.Fieldf("ISSUER_URL", "the verifier needs this issuer and its keys")
	}
	if len(c.Audiences) == 0 {
		return nil, core.Fieldf("AUTHORITY_AUDIENCES", "empty")
	}
	if _, dup := c.Peers[c.SelfIssuer]; dup {
		return nil, core.Fieldf("ISSUER_URL", "a peer has this issuer's own iss")
	}
	if c.RetryEvery <= 0 {
		c.RetryEvery = 30 * time.Second
	}
	v := &Verifier{cfg: c, peers: map[string]*auth.Verifier{}}
	if err := v.Rebuild(); err != nil {
		return nil, err
	}
	for iss := range c.Peers {
		v.tryPeer(ctx, iss)
	}
	return v, nil
}

func (v *Verifier) config(issuers map[string]auth.IssuerConfig) auth.Config {
	return auth.Config{
		Issuers: issuers, Audiences: slices.Clone(v.cfg.Audiences), StrictSessionClaims: true,
		MaxSkew: v.cfg.MaxSkew, HTTPClient: v.cfg.HTTPClient, Now: v.cfg.Now,
	}
}

// Rebuild installs this issuer's current token keys. The signing-key
// manager calls it after every refresh, so a rotation on any replica and
// the end of a retired key's 24 h are followed.
func (v *Verifier) Rebuild() error {
	set, err := v.cfg.SelfKeys(v.cfg.now())
	if err == nil && set.Len() == 0 {
		err = errors.New("this issuer publishes no token key")
	}
	var sv *auth.Verifier
	if err == nil {
		sv, err = auth.NewVerifier(context.Background(), v.config(map[string]auth.IssuerConfig{v.cfg.SelfIssuer: {Keys: set}}))
	}
	if err != nil {
		v.counters.Inc(CounterSelfRebuildFailed)
		return err
	}
	v.self.Store(sv)
	return nil
}

func (v *Verifier) tryPeer(ctx context.Context, iss string) {
	p := v.cfg.Peers[iss]
	pv, err := auth.NewVerifier(ctx, v.config(map[string]auth.IssuerConfig{iss: {JWKSURL: p.JWKSURL, Keys: p.Keys}}))
	if err != nil {
		v.counters.Inc(CounterPeerFetchFailed)
		logging.Error(ctx, v.logger(), "peer issuer not ready; its tokens are refused until its JWKS is fetched", err,
			slog.String("issuer", iss))
		return
	}
	v.mu.Lock()
	v.peers[iss] = pv
	v.mu.Unlock()
}

// Run retries the peers that were not ready, on its own context (E-14),
// until each is or ctx ends.
func (v *Verifier) Run(ctx context.Context) {
	t := time.NewTicker(v.cfg.RetryEvery)
	defer t.Stop()
	for {
		pending := v.Pending()
		if len(pending) == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, iss := range pending {
			fctx, cancel := context.WithTimeout(ctx, auth.DefaultJWKSFetchTimeout+time.Second)
			v.tryPeer(fctx, iss)
			cancel()
		}
	}
}

// Pending lists the configured peers not ready yet.
func (v *Verifier) Pending() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	var out []string
	for _, iss := range slices.Sorted(maps.Keys(v.cfg.Peers)) {
		if v.peers[iss] == nil {
			out = append(out, iss)
		}
	}
	return out
}

// Verify verifies token. Every refusal is a *auth.TokenError.
func (v *Verifier) Verify(ctx context.Context, token string) (auth.Claims, error) {
	cl, err := v.verify(ctx, token)
	if err != nil {
		var te *auth.TokenError
		if errors.As(err, &te) {
			v.counters.Inc(te.Counter)
		}
		return auth.Claims{}, err
	}
	v.counters.Inc(auth.CounterAccepted)
	return cl, nil
}

func (v *Verifier) verify(ctx context.Context, token string) (auth.Claims, error) {
	iss := tokens.UnverifiedIssuer(token)
	if iss != "" && iss != v.cfg.SelfIssuer {
		if _, configured := v.cfg.Peers[iss]; configured {
			v.mu.RLock()
			pv := v.peers[iss]
			v.mu.RUnlock()
			if pv == nil {
				return auth.Claims{}, &auth.TokenError{Counter: CounterIssuerUnavailable, Claim: "iss", Reason: "the issuer's JWKS has not been fetched yet"}
			}
			return pv.Verify(ctx, token)
		}
	}
	return v.self.Load().Verify(ctx, token)
}

// Counters are the verdicts (core's counter names) and this wiring's own
// counters.
func (v *Verifier) Counters() *core.Counters { return &v.counters }

// StatusAttrs puts the peers not ready on the status line.
func (v *Verifier) StatusAttrs() []slog.Attr {
	return []slog.Attr{slog.Any("peer_issuers_pending", v.Pending())}
}

func (v *Verifier) logger() *slog.Logger {
	if v.cfg.Logger == nil {
		return logging.Discard()
	}
	return v.cfg.Logger
}
