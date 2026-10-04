package regimport

import (
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
)

// Setup is what Assemble needs from the process configuration.
type Setup struct {
	DB         *pg.DB
	Registry   Registry
	RulesFile  string
	URL        string
	TokenFile  string
	Timeout    time.Duration
	MaxBytes   int
	MaxRecords int
	// WriteTimeout bounds one import's transaction.
	WriteTimeout time.Duration
	Logger       *slog.Logger
	Limiter      *logging.Limiter
}

// Parts is the assembled import: the service and, when the agreed URL is
// configured, the re-import job.
type Parts struct {
	Service  *Service
	Job      *Job
	Counters *core.Counters
}

// Assemble loads the rules file (a bad one stops the start, naming the
// field) and builds the re-import job when the agreed URL is set (G-11).
func Assemble(s Setup) (*Parts, error) {
	counters := &core.Counters{}
	svc := &Service{
		Registry: s.Registry, Ledger: PG{DB: s.DB}, MaxBytes: s.MaxBytes, MaxRecords: s.MaxRecords,
		WriteTimeout: s.WriteTimeout, Counters: counters, Logger: s.Logger,
	}
	if s.RulesFile != "" {
		rules, err := LoadRules(s.RulesFile)
		if err != nil {
			return nil, err
		}
		svc.Rules = rules
	}
	out := &Parts{Service: svc, Counters: counters}
	if s.URL == "" {
		return out, nil
	}
	if svc.Rules == nil {
		return nil, core.Fieldf("REGISTRY_IMPORT_URL", "needs REGISTRY_IMPORT_RULES_FILE")
	}
	if err := CheckURL(s.URL); err != nil {
		return nil, err
	}
	tok, err := LoadToken(s.TokenFile)
	if err != nil {
		return nil, err
	}
	out.Job = &Job{
		Service: svc, Locker: PGLocker{DB: s.DB}, Limiter: s.Limiter,
		Fetcher: Fetcher{URL: s.URL, Token: tok, MaxBytes: s.MaxBytes, Client: NewClient(s.Timeout)},
	}
	return out, nil
}
