package registry

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Setup is what Assemble needs from the process configuration.
type Setup struct {
	DB          *pg.DB
	Audit       *audit.Writer
	PIIKeyID    string
	PIIKeyFile  string
	HashKeyFile string
	// TSURL, TSRole and TSMaxConns open the projection pool.
	TSURL            string
	TSRole           string
	TSMaxConns       int
	StatementTimeout time.Duration
	Pattern          PatternSource
	MTOMBandsG       []int
	Publisher        Publisher
	Logger           *slog.Logger
}

// Parts is the assembled registry.
type Parts struct {
	Service   *Service
	Handler   Handler
	Counters  *core.Counters
	Projector *ts.Projector
}

// Assemble loads the PII key and the registry hash key, opens the
// projection pool as the projector role and builds the service.
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	sealer, err := pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile)
	if err != nil {
		return nil, err
	}
	hasher, err := LoadHasher(s.HashKeyFile)
	if err != nil {
		return nil, err
	}
	projector, err := ts.OpenProjector(ctx, store.PoolOptions{
		URL: s.TSURL, MaxConns: s.TSMaxConns, StatementTimeout: s.StatementTimeout,
		ApplicationName: "uspace-authority-api", Role: s.TSRole,
	})
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	pub := s.Publisher
	if pub == nil {
		pub = NopPublisher{}
	}
	svc := &Service{
		Store: PG{DB: s.DB, Audit: s.Audit}, Projection: TSProjection{P: projector}, Sealer: sealer, Hasher: hasher,
		Pattern: s.Pattern, Publisher: pub, Counters: counters, Logger: s.Logger, MTOMBandsG: s.MTOMBandsG,
	}
	return &Parts{Service: svc, Handler: Handler{Service: svc}, Counters: counters, Projector: projector}, nil
}

// Close closes the projection pool.
func (p *Parts) Close() { p.Projector.Close() }
