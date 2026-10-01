package authz

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Setup is what Assemble needs from the process configuration.
type Setup struct {
	Store       Store
	Hasher      *passhash.Hasher
	Keys        *tokens.Keys
	PIIKeyID    string
	PIIKeyFile  string
	Audiences   []string
	Peers       map[string]string // iss -> JWKS URL
	Config      Config
	IPPerMin    float64
	IPBurst     int
	UserPerMin  float64
	UserBurst   int
	MaxRateKeys int
	Logger      *slog.Logger
}

// Parts is the assembled console authentication.
type Parts struct {
	Service       *Service
	Verifier      *Verifier
	Authenticator *Authenticator
	Handler       Handler
	Counters      *core.Counters
}

// Assemble loads the PII key and builds the service, the verifier
// wiring and the authenticator.
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	sealer, err := pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile)
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	svc := &Service{
		Store: s.Store, Hasher: s.Hasher, Sealer: sealer, Keys: s.Keys, Counters: counters, Logger: s.Logger, Config: s.Config,
		IPLimiter:   httpx.NewRateLimiter(s.IPPerMin/60, s.IPBurst, s.MaxRateKeys, counters),
		UserLimiter: httpx.NewRateLimiter(s.UserPerMin/60, s.UserBurst, s.MaxRateKeys, counters),
	}
	peers := map[string]Peer{}
	for iss, u := range s.Peers {
		peers[iss] = Peer{JWKSURL: u}
	}
	v, err := NewVerifier(ctx, VerifierConfig{
		SelfIssuer: s.Keys.Issuer(), SelfKeys: s.Keys.TokenKeys, Audiences: s.Audiences, Peers: peers,
		Now: s.Config.Now, Logger: s.Logger,
	})
	if err != nil {
		return nil, err
	}
	return &Parts{
		Service: svc, Verifier: v, Counters: counters, Handler: Handler{Service: svc},
		Authenticator: &Authenticator{Verifier: v, Sessions: svc, SelfIssuer: s.Keys.Issuer()},
	}, nil
}

// OnKeysChanged rebuilds this issuer's key set in the verifier; the
// signing-key manager calls it after each refresh.
func (p *Parts) OnKeysChanged(logger *slog.Logger) func() {
	return func() {
		if err := p.Verifier.Rebuild(); err != nil {
			logger.Error("own key set not rebuilt; the previous set verifies on", slog.String("error", err.Error()))
		}
	}
}

// Run runs the background work until ctx ends: the peer retries and the
// session sweep.
func (p *Parts) Run(ctx context.Context, sweepEvery time.Duration) {
	done := make(chan struct{})
	go func() { defer close(done); p.Verifier.Run(ctx) }()
	p.Service.RunSweep(ctx, sweepEvery)
	<-done
}
