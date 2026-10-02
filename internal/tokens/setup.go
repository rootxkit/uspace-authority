package tokens

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/passhash"
)

// Setup is what Assemble needs from the process configuration.
type Setup struct {
	Issuer             string
	SigningKeyFiles    []string
	PublicationKeyFile string
	TTL                time.Duration
	RetireGrace        time.Duration
	TwoPerson          bool
	ConfirmWindow      time.Duration
	RatePerMin         float64
	RateBurst          int
	RateMaxClients     int
	Store              Store
	Hasher             *passhash.Hasher
	Logger             *slog.Logger
	Now                func() time.Time
}

// Parts is the assembled token service.
type Parts struct {
	Keys     *Keys
	Manager  *KeyManager
	Service  *Service
	Registry *Registry
	Handler  Handler
	// Counters are the token service's counters (status line, /metrics).
	Counters *core.Counters
}

// Assemble loads the key files, registers and activates them in
// signing_keys (KeyManager.Sync) and builds the service. Every key
// problem is an error naming its variable: the process does not start
// without a key it can sign with (E-02).
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	if len(s.SigningKeyFiles) == 0 {
		return nil, core.Fieldf("SIGNING_KEY_FILES", "required: the issuer cannot sign without a key")
	}
	var errs []error
	files := make([]KeyFile, 0, len(s.SigningKeyFiles))
	for _, ref := range s.SigningKeyFiles {
		f, err := LoadKeyFile("SIGNING_KEY_FILES", ref)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		files = append(files, f)
	}
	var pub *KeyFile
	if s.PublicationKeyFile != "" {
		f, err := LoadKeyFile("PUBLICATION_KEY_FILE", s.PublicationKeyFile)
		if err != nil {
			errs = append(errs, err)
		} else {
			pub = &f
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	keys, err := NewKeys(s.Issuer, s.RetireGrace, files, pub)
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	mgr := &KeyManager{
		Store: s.Store, Keys: keys, Counters: counters, Logger: s.Logger,
		TwoPerson: s.TwoPerson, ConfirmWindow: s.ConfirmWindow, Now: s.Now,
	}
	if err := mgr.Sync(ctx); err != nil {
		return nil, err
	}
	svc := &Service{
		Store: s.Store, Keys: keys, Hasher: s.Hasher,
		Limiter:  httpx.NewRateLimiter(s.RatePerMin/60, s.RateBurst, s.RateMaxClients, counters),
		Counters: counters, Logger: s.Logger,
		Config: ServiceConfig{TokenEndpoint: s.Issuer + "/oauth/token", TTL: s.TTL, Now: s.Now},
	}
	reg := &Registry{Store: s.Store, Hasher: s.Hasher, Now: s.Now}
	return &Parts{
		Keys: keys, Manager: mgr, Service: svc, Registry: reg, Counters: counters,
		Handler: Handler{Service: svc, Registry: reg, Manager: mgr, Now: s.Now},
	}, nil
}

// StatusAttrs are the token service's status-line attributes: the kid
// that signs.
func (p *Parts) StatusAttrs() []slog.Attr {
	return []slog.Attr{slog.String("signing_kid", p.Keys.ActiveKID())}
}
