package retention

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/certs"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Setup is what api hands to Assemble.
type Setup struct {
	DB     *pg.DB
	Audit  *audit.Writer
	Config config.Retention
	// The telemetry database, as the archiver role.
	TSURL            string
	TSMaxConns       int
	StatementTimeout time.Duration
	// Packs re-verifies the evidence packs; nil: that job is not run.
	Packs *incidents.Packs
	// Records fetches the USSP daily bundles; nil or without a client:
	// every day is missing with that reason.
	Records *incidents.Records
	Logger  *slog.Logger
	Limiter *logging.Limiter
}

// Parts are the assembled component.
type Parts struct {
	Service   *Service
	Holds     *Holds
	Handler   Handler
	Verifier  *audit.ChainVerifier
	Daily     *certs.DailyRecords
	Scheduler *Scheduler
	Counters  *core.Counters
}

// Assemble builds the retention service, the holds, the chain
// verifier, the daily records pull and the scheduler of their jobs. A
// missing archive store is said at error level: the control plane still
// starts, nothing is archived and so nothing is dropped.
func Assemble(ctx context.Context, s Setup) (*Parts, error) {
	c := s.Config
	logger := s.Logger
	if logger == nil {
		logger = logging.Discard()
	}
	counters := &core.Counters{}
	arch, err := ts.OpenArchiver(ctx, store.PoolOptions{URL: s.TSURL, Role: c.TSArchiverRole, MaxConns: s.TSMaxConns,
		StatementTimeout: s.StatementTimeout, ApplicationName: "uspace-authority-api-archive"})
	if err != nil {
		return nil, err
	}
	arch.ExportTimeout = time.Duration(c.RetentionExportTimeoutS) * time.Second
	st, err := archive.Open(c.ArchiveURL)
	switch {
	case errors.Is(err, archive.ErrNotConfigured):
		st = nil
		logger.Error("no archive store: telemetry beyond the online window is neither archived nor dropped, and no USSP daily records are kept",
			slog.String("variable", "ARCHIVE_URL"), slog.Int("online_days", c.RetentionOnlineDays))
	case err != nil:
		arch.Close()
		return nil, err
	}
	svc := &Service{DB: s.DB, Audit: s.Audit, TS: arch, Store: st,
		Periods: Periods{OnlineDays: c.RetentionOnlineDays, ArchiveYears: c.RetentionArchiveYears,
			ViolationsYears: c.RetentionViolationsYears, AuditYears: c.RetentionAuditYears, Incidents: c.RetentionIncidents},
		BatchRows: c.RetentionBatchRows, MaxBatches: c.RetentionMaxBatches, ChunksPerRun: c.RetentionChunksPerRun,
		IncidentMargin: time.Duration(c.RetentionMarginS) * time.Second, MaxHolds: c.RetentionMaxHolds,
		Counters: counters, Logger: logger, Limiter: s.Limiter}
	holds := &Holds{DB: s.DB, Audit: s.Audit, WriteTimeout: 10 * time.Second, Counters: counters}
	verifier := audit.NewChainVerifier(s.Audit, counters, logger)
	if err := verifier.Load(ctx); err != nil {
		arch.Close()
		return nil, err
	}
	daily := &certs.DailyRecords{DB: s.DB, Audit: s.Audit, Store: st, GraceDays: c.USSPRecordsGraceDays,
		BackfillDays: c.USSPRecordsBackfill, Timeout: time.Duration(c.USSPRecordsTimeoutS) * time.Second,
		MaxBytes: int64(c.ArchiveMaxObjectBytes), MaxUSSPs: c.USSPRecordsMaxUSSPs, Counters: counters, Logger: logger}
	if s.Records != nil && s.Records.Tokens != nil {
		daily.Fetcher = s.Records
	} else {
		logger.Warn("USSP daily records cannot be fetched until a records client is configured; every day is missing with that reason",
			slog.String("variable", "RECORDS_CLIENT_SECRET_FILE"))
	}
	if err := daily.Load(ctx); err != nil {
		arch.Close()
		return nil, err
	}
	every := time.Duration(c.RetentionEveryS) * time.Second
	jobs := []Job{
		{Name: JobRetention, Every: every, Run: svc.Run},
		{Name: JobAuditVerify, Monthly: true, Run: verifier.VerifyAll},
		{Name: JobUSSPRecords, Every: every, Run: daily.RunOnce},
	}
	if s.Packs != nil {
		maxPacks := c.EvidenceVerifyMax
		jobs = append(jobs, Job{Name: JobEvidenceVerify, Monthly: true, Run: func(ctx context.Context) (map[string]any, error) {
			return s.Packs.ReverifyAll(ctx, maxPacks)
		}})
	}
	sched := &Scheduler{DB: s.DB, Jobs: jobs, Tick: time.Duration(c.RetentionTickS) * time.Second,
		Retry: time.Duration(c.RetentionRetryS) * time.Second, Counters: counters, Logger: logger, Limiter: s.Limiter}
	logger.Info("retention ready", slog.Int("online_days", c.RetentionOnlineDays), slog.Int("archive_years", c.RetentionArchiveYears),
		slog.Int("violations_years", c.RetentionViolationsYears), slog.String("incidents", c.RetentionIncidents),
		slog.Int("audit_years", c.RetentionAuditYears), slog.Bool("pending_gcaa", PendingGCAA),
		slog.Bool("archive_store", st != nil), slog.Bool("records_client", daily.Fetcher != nil))
	return &Parts{Service: svc, Holds: holds, Handler: Handler{Holds: holds, Service: svc}, Verifier: verifier, Daily: daily,
		Scheduler: sched, Counters: counters}, nil
}

// StatusAttrs are the component's entries on the status line.
func (p *Parts) StatusAttrs() []slog.Attr {
	attrs := p.Service.StatusAttrs()
	attrs = append(attrs, p.Verifier.StatusAttrs()...)
	attrs = append(attrs, p.Daily.StatusAttrs()...)
	return append(attrs, p.Scheduler.StatusAttrs()...)
}

// Close closes the archiver pool.
func (p *Parts) Close() { p.Service.TS.Close() }
