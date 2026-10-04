package regimport

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/registry"
)

// Counters of the import (status line and /metrics, E-09).
const (
	CounterNotConfigured  = "registry_import_not_configured"  // an import asked for without a rules file
	CounterUnreadable     = "registry_import_unreadable"      // a file that could not be read as its format, or over a bound
	CounterLedgerFailed   = "registry_import_ledger_failed"   // an import ran but its registry_imports row was not written
	CounterFetched        = "registry_import_fetched"         // exports fetched from REGISTRY_IMPORT_URL
	CounterFetchFailed    = "registry_import_fetch_failed"    // a fetch that failed (unreachable, not 200, too large)
	CounterFetchUnchanged = "registry_import_fetch_unchanged" // a fetched export run to an outcome before, not run again
	CounterFetchSkipped   = "registry_import_fetch_skipped"   // another replica held the fetch job's lock
	CounterTimeout        = "registry_import_timeout"         // an import past REGISTRY_IMPORT_WRITE_TIMEOUT_S, rolled back
)

// SlugNotConfigured is the problem slug of an import without a rules
// file.
const SlugNotConfigured = "import_not_configured"

// Origins of an import.
const (
	OriginUpload = "upload"
	OriginFetch  = "fetch"
)

// Outcomes in the ledger.
const (
	OutcomeApplied = "applied"
	OutcomeRefused = "refused"
)

// MaxReportOutcomes bounds the outcomes a report lists (E-10).
const MaxReportOutcomes = 1000

// Entry is one registry_imports row.
type Entry struct {
	ID           string
	At           time.Time
	Kind         string
	Origin       string
	SHA256       string
	RulesVersion string
	Outcome      string
	Records      int
	Created      int
	Updated      int
	Unchanged    int
	Problems     int
	Version      int64
	ActorID      string
}

// Ledger is where every import that ran to an outcome is recorded; the
// re-import job reads it so content it ran before is not run again.
type Ledger interface {
	Record(ctx context.Context, e Entry) error
	Last(ctx context.Context, kind, origin string) (Entry, bool, error)
}

// Registry is what the import needs of internal/registry.
type Registry interface {
	ImportOperators(ctx context.Context, rows []registry.ImportedOperator, o registry.ImportOptions, actor audit.Actor) (registry.ImportResult, error)
	ImportUAS(ctx context.Context, rows []registry.ImportedUAS, o registry.ImportOptions, actor audit.Actor) (registry.ImportResult, error)
}

// Service imports uas.gov.ge exports under the rules file.
type Service struct {
	Registry Registry
	Ledger   Ledger
	// Rules is nil when REGISTRY_IMPORT_RULES_FILE is not configured:
	// every import is refused 503 import_not_configured.
	Rules      *Rules
	MaxBytes   int
	MaxRecords int
	// WriteTimeout bounds one import's transaction (E-10): an upload is
	// answered within the listener's write timeout, so a transaction
	// past it is rolled back (503 import_timeout) instead of committing
	// after its caller was cut off. Zero is no bound.
	WriteTimeout time.Duration
	Counters     *core.Counters
	Logger       *slog.Logger
}

// SlugTimeout is the problem slug of an import past WriteTimeout.
const SlugTimeout = "import_timeout"

func (s *Service) count(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

// Report is the outcome of one import or dry run.
type Report struct {
	registry.ImportResult
	RulesVersion string
	SHA256       string
}

// Request is one import to run.
type Request struct {
	Kind   string
	Format string
	Body   []byte
	DryRun bool
	Origin string
}

func newEntryID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Run reads the export, maps it under the rules and imports it through
// the registry, all or nothing. Everything is checked before anything
// is written (the rules, the bounds, every record); a file that cannot
// be read is a 400 naming where; a file whose records have problems is
// imported not at all and reported with every problem (the caller
// answers 422, or 200 for a dry run). An import that ran to an outcome
// (applied or refused) is recorded in the ledger after its transaction.
func (s *Service) Run(ctx context.Context, req Request, actor audit.Actor) (Report, error) {
	if s.Rules == nil {
		s.count(CounterNotConfigured)
		return Report{}, httpx.Refuse(http.StatusServiceUnavailable, SlugNotConfigured,
			"no rules file is configured (REGISTRY_IMPORT_RULES_FILE): an export cannot be read without the mapping agreed with GCAA")
	}
	if req.Kind != registry.ImportKindOperators && req.Kind != registry.ImportKindUAS {
		return Report{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", core.Fieldf("kind", "must be operators or uas"))
	}
	if s.MaxBytes > 0 && len(req.Body) > s.MaxBytes {
		s.count(CounterUnreadable)
		return Report{}, httpx.Refuse(http.StatusRequestEntityTooLarge, httpx.SlugBodyTooLarge, "",
			core.Fieldf("body", "longer than %d bytes (REGISTRY_IMPORT_MAX_BYTES)", s.MaxBytes))
	}
	sum := sha256.Sum256(req.Body)
	rep := Report{RulesVersion: s.Rules.RulesVersion, SHA256: hex.EncodeToString(sum[:])}
	maxRecords := s.MaxRecords
	if maxRecords <= 0 || maxRecords > registry.MaxImportRecords {
		maxRecords = registry.MaxImportRecords
	}
	delim, _ := utf8.DecodeRuneInString(s.Rules.CSV.Delimiter)
	if s.Rules.CSV.Delimiter == "" {
		delim = ','
	}
	recs, readProblems, err := ReadRecords(req.Body, req.Format, delim, maxRecords)
	if err != nil {
		s.count(CounterUnreadable)
		return Report{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "the export cannot be read", fieldErrs(err)...)
	}
	opts := registry.ImportOptions{
		DryRun: req.DryRun, Origin: req.Origin, SHA256: rep.SHA256, RulesVersion: rep.RulesVersion, Records: len(recs),
	}
	var res registry.ImportResult
	runCtx := ctx
	if s.WriteTimeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, s.WriteTimeout)
		defer cancel()
	}
	switch req.Kind {
	case registry.ImportKindOperators:
		rows, problems := MapOperators(s.Rules, recs)
		opts.Problems = slices.Concat(readProblems, problems)
		res, err = s.Registry.ImportOperators(runCtx, rows, opts, actor)
	default:
		rows, problems := MapUAS(s.Rules, recs)
		opts.Problems = slices.Concat(readProblems, problems)
		res, err = s.Registry.ImportUAS(runCtx, rows, opts, actor)
	}
	if err != nil && runCtx.Err() != nil && ctx.Err() == nil {
		s.count(CounterTimeout)
		return Report{}, httpx.Refuse(http.StatusServiceUnavailable, SlugTimeout, fmt.Sprintf(
			"the import did not finish within %s (REGISTRY_IMPORT_WRITE_TIMEOUT_S) and was rolled back: nothing was written; split the export",
			s.WriteTimeout))
	}
	if err != nil {
		return Report{}, err
	}
	annotate(res.Problems, s.Rules.Columns(req.Kind))
	rep.ImportResult = res
	if !req.DryRun {
		s.ledger(ctx, &rep, req, actor)
	}
	return rep, nil
}

// annotate names the column beside a registry problem about a mapped
// field, as the mapper does for its own.
func annotate(ps []*core.FieldError, columns map[string]string) {
	for _, p := range ps {
		_, field, ok := strings.Cut(p.Field, "].")
		if !ok {
			continue
		}
		if col, mapped := columns[field]; mapped && !strings.HasPrefix(p.Reason, "column ") {
			p.Reason = fmt.Sprintf("column %q: %s", col, p.Reason)
		}
	}
}

func fieldErrs(err error) []*core.FieldError {
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return []*core.FieldError{fe}
	}
	return []*core.FieldError{{Field: "body", Reason: err.Error()}}
}

func (s *Service) ledger(ctx context.Context, rep *Report, req Request, actor audit.Actor) {
	if s.Ledger == nil {
		return
	}
	id, err := newEntryID()
	if err == nil {
		outcome := OutcomeApplied
		if !rep.Applied() {
			outcome = OutcomeRefused
		}
		err = s.Ledger.Record(context.WithoutCancel(ctx), Entry{
			ID: id, Kind: req.Kind, Origin: req.Origin, SHA256: rep.SHA256, RulesVersion: rep.RulesVersion, Outcome: outcome,
			Records: rep.Records, Created: rep.Created, Updated: rep.Updated, Unchanged: rep.Unchanged, Problems: len(rep.Problems),
			Version: rep.Version, ActorID: actor.ID,
		})
	}
	if err != nil {
		// The import itself stands (its events row is the audit record);
		// without its ledger row the re-import job runs the same content
		// again, which the idempotent import answers unchanged.
		s.count(CounterLedgerFailed)
		logging.Error(ctx, s.logger(), "registry import ran but its registry_imports row was not written", err,
			slog.String("kind", req.Kind), slog.String("content_sha256", rep.SHA256))
	}
}
