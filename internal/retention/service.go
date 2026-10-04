package retention

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// Periods are the retention periods in force (config.Retention; spec
// 05 §4 and 08 Q8 defaults, pending GCAA).
type Periods struct {
	OnlineDays      int
	ArchiveYears    int
	ViolationsYears int
	AuditYears      int
	// Incidents is "indefinite", the only value implemented.
	Incidents string
}

// PendingGCAA is true while the periods are the spec's defaults: GCAA
// and the DPO have not answered Q8. It is said on the status line and
// in GET /v1/retention/status, never dropped silently.
const PendingGCAA = true

// Actor is the actor of the retention job's events rows.
const Actor = "retention"

// Entity types of the job's events rows.
const (
	EntityChunk      = "archive_chunk"
	EntityViolations = "violations"
	EntityEvents     = "events"
	EntityUSSPDay    = "ussp_daily_records"
)

// Counters of the retention job (E-09).
const (
	CounterChunksArchived      = "retention_chunks_archived"
	CounterChunksDropped       = "retention_chunks_dropped"
	CounterChunksHeld          = "retention_chunks_held"            // archived, kept online: a hold or an open incident names it
	CounterChunksFailed        = "retention_chunk_failures"         // an export, verification or drop that failed; the chunk stays online
	CounterChunksBounded       = "retention_chunks_bounded"         // chunks past RETENTION_CHUNKS_PER_RUN left for the next run
	CounterArchiveUnconfigured = "retention_archive_unconfigured"   // a run with no archive store: nothing archived, nothing dropped
	CounterRowsRedacted        = "retention_frames_pii_redacted"    // remote pilot positions removed from archived frames
	CounterPayloadsDropped     = "retention_frames_payload_dropped" // undecodable frames whose payload was left out of the archive
	CounterViolationsDeleted   = "retention_violations_deleted"
	CounterBatchesBounded      = "retention_batches_bounded" // deletions past RETENTION_MAX_BATCHES left for the next run
	CounterAuditMonthsDropped  = "retention_audit_months_dropped"
	CounterAuditMonthsHeld     = "retention_audit_months_held"
	CounterObjectsDeleted      = "retention_objects_deleted"
	CounterObjectsHeld         = "retention_objects_held"
	CounterHoldsBound          = "retention_holds_bound" // more holds or incident aircraft than a check reads: everything held (fail closed)
	CounterAuditCaughtUp       = "retention_audit_caught_up"
)

// Service runs the retention steps. Each step bounds its work per run,
// commits each change with its events row (or, for a change in the
// telemetry database, records the events row after that commit and
// catches up on a restart), and never touches a held record.
type Service struct {
	DB    *pg.DB
	Audit *audit.Writer
	// TS is the archiver pool on the telemetry database.
	TS *ts.Archiver
	// Store is the archive store; nil: nothing is archived, so no chunk
	// is dropped, and the run says so at error level.
	Store   archive.Store
	Periods Periods

	BatchRows      int
	MaxBatches     int
	ChunksPerRun   int
	IncidentMargin time.Duration
	MaxHolds       int

	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter

	mu   sync.Mutex
	last map[string]any
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

func (s *Service) inc(name string) { s.add(name, 1) }

func (s *Service) add(name string, n int64) {
	if s.Counters != nil && n > 0 {
		s.Counters.Add(name, uint64(n))
	}
}

func (s *Service) actor() audit.Actor { return audit.SystemActor(Actor) }

// recordOnce writes an events row of eventType naming the chunk entityID unless
// one is recorded already (a step recorded after a commit in the
// telemetry database is recorded once, also when a restart repeats it).
func (s *Service) recordOnce(ctx context.Context, q *gen.Queries, entityID, eventType string, payload map[string]any) error {
	entityType := EntityChunk
	done, err := q.EventRecorded(ctx, gen.EventRecordedParams{EntityType: entityType, EntityID: &entityID, EventType: eventType})
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	_, err = s.Audit.Record(ctx, q, audit.Event{Actor: s.actor(), EntityType: entityType, EntityID: entityID,
		EventType: eventType, Payload: payload})
	return err
}

// Run is the daily retention job: archive and drop the telemetry beyond
// its online window, delete the expired archive objects, the expired
// violations and the expired months of the audit log. Every step runs
// even when one before it failed (an unreachable archive store must not
// stop the deletion of violations); the run fails when any step did,
// and its summary says what each step did, in numbers.
func (s *Service) Run(ctx context.Context) (map[string]any, error) {
	sum := map[string]any{"periods": s.periodsMap()}
	var errs []error
	steps := []struct {
		name string
		fn   func(context.Context) (map[string]any, error)
	}{
		{"telemetry", s.ArchiveTelemetry},
		{"archive_expiry", s.ExpireArchive},
		{"violations", s.DeleteViolations},
		{"audit", s.DropAuditMonths},
	}
	for _, st := range steps {
		r, err := st.fn(ctx)
		if r == nil {
			r = map[string]any{}
		}
		if err != nil {
			r["error"] = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", st.name, err))
			s.logger().Error("retention step failed; what it did not reach stays as it was",
				slog.String("step", st.name), slog.String("error", err.Error()))
		}
		sum[st.name] = r
	}
	s.mu.Lock()
	s.last = sum
	s.mu.Unlock()
	return sum, errors.Join(errs...)
}

func (s *Service) periodsMap() map[string]any {
	return map[string]any{"online_days": s.Periods.OnlineDays, "archive_years": s.Periods.ArchiveYears,
		"violations_years": s.Periods.ViolationsYears, "audit_years": s.Periods.AuditYears,
		"incidents": s.Periods.Incidents, "pending_gcaa": PendingGCAA}
}

// StatusAttrs are the retention entries of the status line: the periods
// (pending GCAA), the archive store and the last run's numbers.
func (s *Service) StatusAttrs() []slog.Attr {
	store := "none"
	if s.Store != nil {
		store = s.Store.Describe()
	}
	attrs := []slog.Attr{
		slog.Int("retention_online_days", s.Periods.OnlineDays), slog.Int("retention_archive_years", s.Periods.ArchiveYears),
		slog.Int("retention_violations_years", s.Periods.ViolationsYears), slog.Int("retention_audit_years", s.Periods.AuditYears),
		slog.String("retention_incidents", s.Periods.Incidents), slog.Bool("retention_pending_gcaa", PendingGCAA),
		slog.String("archive_store", store),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		return append(attrs, slog.String("retention_last_run", "none in this process"))
	}
	if t, ok := s.last["telemetry"].(map[string]any); ok {
		attrs = append(attrs, slog.Any("retention_last_telemetry", t))
	}
	return attrs
}
