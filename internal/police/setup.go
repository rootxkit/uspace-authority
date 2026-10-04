package police

import (
	"context"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Setup is what api hands to Assemble.
type Setup struct {
	DB       *pg.DB
	Audit    *audit.Writer
	Config   config.Police
	Accounts Accounts
	Registry Registry
	// Incidents and Packs are WP-17's case files and evidence packs.
	Incidents Incidents
	Packs     Packs
	// The telemetry database, read as the reader role.
	TSURL            string
	TSRole           string
	TSMaxConns       int
	StatementTimeout time.Duration
	// Pattern is the active policy's registration-number pattern.
	Pattern func() (string, bool)
	Logger  *slog.Logger
}

// Parts are the assembled police realm.
type Parts struct {
	Service  *Service
	Handler  Handler
	Counters *core.Counters
	reader   *ts.Reader
}

// Close closes the telemetry pool.
func (p *Parts) Close() {
	if p.reader != nil {
		p.reader.Close()
	}
}

// Assemble checks the purpose lists (a wrong one stops the start, naming
// the variable), opens the telemetry reader pool and builds the
// service. It says at start which purposes release personal data.
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	c := s.Config
	purposes, err := NewPurposes(c.PolicePurposes, c.PolicePIIPurposes)
	if err != nil {
		return nil, err
	}
	logger := s.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	rd, err := ts.OpenReader(ctx, store.PoolOptions{URL: s.TSURL, Role: s.TSRole, MaxConns: s.TSMaxConns,
		StatementTimeout: s.StatementTimeout, ApplicationName: "uspace-authority-api-police"})
	if err != nil {
		return nil, err
	}
	counters := &core.Counters{}
	svc := &Service{
		Accounts: s.Accounts, Registry: s.Registry, Telemetry: rd.Q, Incidents: s.Incidents, Packs: s.Packs,
		Ledger: PG{DB: s.DB, Audit: s.Audit}, Purposes: purposes,
		Budget: Budget{User: c.PoliceUserQueries, Agency: c.PoliceAgencyQueries, Window: time.Duration(c.PoliceRateWindowS) * time.Second},
		Limits: Limits{
			LiveWindow: time.Duration(c.PoliceLiveWindowS) * time.Second, AtWindow: time.Duration(c.PoliceAtWindowS) * time.Second,
			HistoryMax: time.Duration(c.PoliceHistoryMaxAgeS) * time.Second, MaxBBoxDeg: c.PoliceMaxBBoxDeg,
			MaxAircraft: c.PoliceMaxAircraft, MaxPositions: c.PoliceMaxPositions, MaxFleet: c.PoliceMaxFleet,
			DPOMaxRows: c.DPOReportMaxRows, Timeout: time.Duration(c.PoliceWriteTimeoutS) * time.Second,
		},
		PublicPart: incidents.PublicPartOf(s.Pattern), Catalogue: s.Audit.Catalogue, Counters: counters, Logger: logger,
	}
	logger.Info("police realm ready", slog.Any("purposes", purposes.All()), slog.Any("pii_purposes", purposes.PII()),
		slog.Int("user_queries", c.PoliceUserQueries), slog.Int("agency_queries", c.PoliceAgencyQueries),
		slog.Int("rate_window_s", c.PoliceRateWindowS))
	if len(purposes.PII()) == 0 {
		logger.Warn("no police purpose releases personal data: every police answer is status only and legal exports are refused",
			slog.String("variable", "POLICE_PII_PURPOSES"))
	}
	return &Parts{Service: svc, Handler: Handler{Service: svc}, Counters: counters, reader: rd}, nil
}
