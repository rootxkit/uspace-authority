package occurrences

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/logging"
	ostore "github.com/rootxkit/uspace-authority/internal/occurrences/store"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store"
)

// Setup is what api hands to Assemble.
type Setup struct {
	// PGURL is the relational database; the pool works as Config's
	// PG_OCCURRENCES_ROLE, never as api's application role.
	PGURL            string
	StatementTimeout time.Duration
	Audit            *audit.Writer
	Config           config.Occurrences
	// The PII key, which the occurrence key must not be (plan D9).
	PIIKeyID, PIIKeyFile string
	// Pattern is the active policy's registration-number pattern.
	Pattern func() (string, bool)
	Logger  *slog.Logger
	Limiter *logging.Limiter
}

// Parts are the assembled component.
type Parts struct {
	Service  *Service
	Handler  Handler
	Counters *core.Counters
	db       *ostore.DB
}

// Ping checks the occurrences pool (a readiness check).
func (p *Parts) Ping(ctx context.Context) error { return p.db.Ping(ctx) }

// Close closes the occurrences pool.
func (p *Parts) Close() { p.db.Close() }

// Assemble opens the occurrences pool as its own role and builds the
// service. A missing occurrence key is said at start and refuses only
// what needs it; an occurrence key equal to the PII key, an unknown
// export format or an invalid classification scheme stops the start.
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	c := s.Config
	logger := s.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	if err := validRiskClasses(c.OccurrencesRiskClasses); err != nil {
		return nil, err
	}
	exporters := DefaultExporters()
	if _, ok := exporters[c.OccurrencesExportFormat]; !ok {
		return nil, core.Fieldf("OCCURRENCES_EXPORT_FORMAT", "%q is not a format of this build (%v)", c.OccurrencesExportFormat, exporters.Formats())
	}
	var sealer *pii.Sealer
	if c.OccurrenceKeyFile != "" {
		var err error
		if sealer, err = pii.LoadSealerAs("OCCURRENCE_KEY_ID", "OCCURRENCE_KEY_FILE", c.OccurrenceKeyID, c.OccurrenceKeyFile); err != nil {
			return nil, err
		}
		piiSealer, err := pii.LoadSealer(s.PIIKeyID, s.PIIKeyFile)
		if err != nil {
			return nil, err
		}
		if sealer.SameKey(piiSealer) {
			return nil, core.Fieldf("OCCURRENCE_KEY_FILE", "holds the PII key; the occurrence reporter identity needs a key of its own (plan D9, 376/2014 Art. 16)")
		}
	}
	db, err := ostore.Open(ctx, store.PoolOptions{URL: s.PGURL, Role: c.OccurrencesPGRole, MaxConns: c.OccurrencesPGMaxConns,
		StatementTimeout: s.StatementTimeout, ApplicationName: "uspace-authority-api-occurrences"})
	if err != nil {
		return nil, fmt.Errorf("PG_OCCURRENCES_ROLE %s: %w", c.OccurrencesPGRole, err)
	}
	counters := &core.Counters{}
	svc := &Service{Store: PG{DB: db, Audit: s.Audit}, Sealer: sealer, PublicPart: PublicPartOf(s.Pattern),
		Deadline: time.Duration(c.OccurrencesDeadlineS) * time.Second, ClockSkew: time.Duration(c.OccurrencesClockSkewS) * time.Second,
		RiskClasses: c.OccurrencesRiskClasses, Exporters: exporters, DefaultFormat: c.OccurrencesExportFormat,
		MaxExportRecords: c.OccurrencesExportMaxRecord, WriteTimeout: time.Duration(c.OccurrencesWriteTimeoutS) * time.Second,
		Counters: counters, Logger: logger, Limiter: s.Limiter}
	if sealer == nil {
		logger.Error("occurrence reports carrying a reporter reference are refused (503 occurrence_key_unavailable) until OCCURRENCE_KEY_FILE is configured",
			slog.String("variable", "OCCURRENCE_KEY_FILE"))
	}
	keyID := ""
	if sealer != nil {
		keyID = sealer.KeyID()
	}
	logger.Info("occurrences ready", slog.String("role", c.OccurrencesPGRole), slog.Bool("occurrence_key", sealer != nil),
		slog.String("occurrence_key_id", keyID), slog.Int("report_deadline_s", c.OccurrencesDeadlineS),
		slog.Any("risk_classes", c.OccurrencesRiskClasses), slog.String("export_format", c.OccurrencesExportFormat),
		slog.Any("export_formats", exporters.Formats()), slog.Int("export_max_records", c.OccurrencesExportMaxRecord))
	return &Parts{Service: svc, Handler: Handler{Service: svc}, Counters: counters, db: db}, nil
}
