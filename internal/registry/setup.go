package registry

import (
	"log/slog"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
)

// Setup is what Assemble needs from the process configuration.
type Setup struct {
	DB          *pg.DB
	Audit       *audit.Writer
	PIIKeyID    string
	PIIKeyFile  string
	HashKeyFile string
	Pattern     PatternSource
	Logger      *slog.Logger
}

// Parts is the assembled registry.
type Parts struct {
	Service  *Service
	Handler  Handler
	Counters *core.Counters
}

// Assemble loads the PII key and the registry hash key and builds the
// service.
func Assemble(s Setup) (*Parts, error) {
	sealer, err := pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile)
	if err != nil {
		return nil, err
	}
	hasher, err := LoadHasher(s.HashKeyFile)
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	svc := &Service{
		Store: PG{DB: s.DB, Audit: s.Audit}, Sealer: sealer, Hasher: hasher,
		Pattern: s.Pattern, Counters: counters, Logger: s.Logger,
	}
	return &Parts{Service: svc, Handler: Handler{Service: svc}, Counters: counters}, nil
}
