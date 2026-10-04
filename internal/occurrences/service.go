package occurrences

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/pii"
)

// Counters of the occurrence reports (E-09).
const (
	CounterReceived          = "occurrences_received"
	CounterLate              = "occurrences_received_late" // past the reporting deadline: stored and flagged, never refused
	CounterReplayed          = "occurrences_replayed"
	CounterRefRefused        = "occurrences_report_ref_conflict"
	CounterInvalid           = "occurrences_refused_invalid"
	CounterKeyUnavailable    = "occurrences_refused_key_unavailable"
	CounterOrgIgnored        = "occurrences_reporter_org_ignored" // reporter.org differs from the token's sub
	CounterChannelOverridden = "occurrences_operator_channel_mandatory"
	CounterReporterViewed    = "occurrences_reporter_viewed"
	CounterReporterUnopened  = "occurrences_reporter_does_not_open"
	CounterClassified        = "occurrences_classified"
	CounterAnalysed          = "occurrences_analysis_updated"
	CounterExports           = "occurrences_exports"
	CounterExportTooLarge    = "occurrences_export_too_large"
)

// Problem slugs of the occurrence operations.
const (
	SlugKeyUnavailable  = "occurrence_key_unavailable"
	SlugRefConflict     = "report_ref_conflict"
	SlugClosed          = "occurrence_closed"
	SlugNotClassified   = "occurrence_not_classified"
	SlugNotAnalysed     = "occurrence_not_analysed"
	SlugExportTooLarge  = "export_too_large"
	SlugUnknownFormat   = "unknown_export_format"
	SlugReporterUnknown = "reporter_unreadable"
)

// Entity types in events.
const (
	EntityOccurrence = "occurrence"
	EntityExport     = "occurrence_export"
)

// ErrNotFound is a report that does not exist.
var ErrNotFound = httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no occurrence report with this id")

// Tx is one transaction of the occurrences schema with the audit log.
type Tx interface {
	// Now is the database clock of the transaction.
	Now(ctx context.Context) (time.Time, error)
	// Insert stores a report; inserted is false when (reporter_org,
	// report_ref) is held already, and nothing is written.
	Insert(ctx context.Context, r *NewReport) (rep Report, inserted bool, err error)
	ByKey(ctx context.Context, org, ref string) (Report, error)
	Get(ctx context.Context, id string) (Report, error)
	GetForUpdate(ctx context.Context, id string) (Report, error)
	Classify(ctx context.Context, id, class, actor string) (Report, error)
	UpdateAnalysis(ctx context.Context, id, analysis, followUp, state, actor string) (Report, error)
	// Received lists the reports received in [from, to), oldest first, at
	// most limit.
	Received(ctx context.Context, from, to time.Time, limit int) ([]Report, error)
	InsertExport(ctx context.Context, e *Export) error
	Audit(ctx context.Context, ev audit.Event) error
}

// Store holds the reports.
type Store interface {
	WithTx(ctx context.Context, fn func(Tx) error) error
	Get(ctx context.Context, id string) (Report, error)
	List(ctx context.Context, f Filter) ([]Report, error)
}

// Service is the 376/2014 intake and the officers' handling (api only).
type Service struct {
	Store Store
	// Sealer seals the reporter's person reference (OCCURRENCE_KEY_FILE);
	// nil refuses a report carrying one (503) and every sealed identity.
	Sealer     *pii.Sealer
	PublicPart PublicPartFunc
	// Deadline is the reporting deadline after became_aware_at.
	Deadline time.Duration
	// ClockSkew is how far became_aware_at may be ahead of the database
	// clock.
	ClockSkew        time.Duration
	RiskClasses      []string
	Exporters        Exporters
	DefaultFormat    string
	MaxExportRecords int
	WriteTimeout     time.Duration
	Counters         *core.Counters
	Logger           *slog.Logger
	Limiter          *logging.Limiter
	// NewID numbers a report and an export; nil is bus.NewULID.
	NewID func(time.Time) string
}

func (s *Service) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) warn(key string) *slog.Logger {
	if s.Limiter != nil {
		return s.Limiter.Limited(key)
	}
	if s.Logger != nil {
		return s.Logger
	}
	return logging.Discard()
}

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID(time.Now())
	}
	return bus.NewULID(time.Now())
}

func (s *Service) tx(ctx context.Context, fn func(Tx) error) error {
	if s.WriteTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.WriteTimeout)
		defer cancel()
	}
	return s.Store.WithTx(ctx, fn)
}

// Origin is who reports: a machine client (a USSP or the ANSP) by its
// token, or an operator (2019/947 Art. 19(2)) by its registration.
type Origin struct {
	Actor audit.Actor
	// Org is the reporter_org recorded.
	Org string
	// Operator marks an operator's report: always the mandatory channel.
	Operator bool
}

// ClientOrigin is the origin of a report posted with an ecosystem token:
// the token's sub is the reporting organisation.
func ClientOrigin(actor audit.Actor) Origin { return Origin{Actor: actor, Org: actor.ID} }

// OperatorOrigin is the origin of an operator's report (947 Art. 19(2)),
// recorded as operator:<registration public part> on the mandatory
// channel. The portal session that posts it is WP-20's.
func OperatorOrigin(actor audit.Actor, registration string, publicPart PublicPartFunc) (Origin, error) {
	reg := strings.TrimSpace(registration)
	if publicPart != nil {
		reg = publicPart(reg)
	}
	if reg == "" || len(reg) > MaxOrgBytes-len(operatorOrgPrefix) {
		return Origin{}, core.Fieldf("registration", "is not an operator registration number")
	}
	return Origin{Actor: actor, Org: operatorOrgPrefix + reg, Operator: true}, nil
}

// Receipt is the acknowledgement of a report.
type Receipt struct {
	Report   Report
	Replayed bool
}

// Refused counts a body refused before it reached the service (E-09).
func (s *Service) Refused() { s.inc(CounterInvalid) }

// Intake stores a report from o, idempotently on (o.Org, report_ref): the
// same report again answers the first receipt (Replayed), another report
// under the same reference is 409. A late report is stored and flagged.
// A person reference without the occurrence key is 503, never stored in
// clear. Every new report is one occurrence_received events row without
// the reporter's identity, in the transaction that stores it.
func (s *Service) Intake(ctx context.Context, o Origin, in Input) (Receipt, error) {
	if o.Org == "" {
		return Receipt{}, httpx.Refuse(http.StatusUnauthorized, httpx.SlugUnauthn, "no reporting organisation on the request")
	}
	if s.Deadline < time.Second {
		// E-15: without a deadline within_72h means nothing; refuse, never
		// flag every report as on time.
		return Receipt{}, errors.New("occurrences: no reporting deadline configured (OCCURRENCES_REPORT_DEADLINE_S)")
	}
	if in.PersonRef != "" && s.Sealer == nil {
		s.inc(CounterKeyUnavailable)
		return Receipt{}, httpx.Refuse(http.StatusServiceUnavailable, SlugKeyUnavailable,
			"the reporter reference cannot be sealed: OCCURRENCE_KEY_FILE is not configured on this instance; nothing was stored, retry later")
	}
	overridden := false
	if o.Operator && in.Channel != ChannelMandatory {
		in.Channel, overridden = ChannelMandatory, true
		s.inc(CounterChannelOverridden)
	}
	if !o.Operator && in.ReporterOrg != "" && in.ReporterOrg != o.Org {
		s.inc(CounterOrgIgnored)
		s.warn("occurrences_reporter_org_ignored").Warn("an occurrence report names another reporter.org than its token; the token's sub is recorded",
			slog.String("client_id", o.Org), slog.String("reporter_org", in.ReporterOrg))
	}
	origin := OriginClient
	if o.Operator {
		origin = OriginOperator
	}
	id := s.newID()
	nr := &NewReport{ID: id, ReporterOrg: o.Org, Origin: origin, DeadlineS: int(s.Deadline / time.Second), ContentHash: ContentHash(&in), Input: in}
	if in.PersonRef != "" {
		sealed, err := s.Sealer.Seal([]byte(in.PersonRef), []byte(id))
		if err != nil {
			return Receipt{}, err
		}
		nr.PersonSealed, nr.PersonKeyID = sealed, s.Sealer.KeyID()
	}
	var out Receipt
	err := s.tx(ctx, func(tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		if in.BecameAwareAt.After(now.Add(s.ClockSkew)) {
			s.inc(CounterInvalid)
			return core.Fieldf("became_aware_at", "is after the authority's clock (%s) by more than %s", stamp(now), s.ClockSkew)
		}
		rep, inserted, err := tx.Insert(ctx, nr)
		if err != nil {
			return err
		}
		if !inserted {
			held, err := tx.ByKey(ctx, o.Org, in.ReportRef)
			if err != nil {
				return err
			}
			if held.ContentHash != nr.ContentHash {
				s.inc(CounterRefRefused)
				return httpx.Refuse(http.StatusConflict, SlugRefConflict,
					"another report was received under this report_ref from this reporter; a report_ref names one report",
					core.Fieldf("report_ref", "names another report received at %s", stamp(held.ReceivedAt)))
			}
			out = Receipt{Report: held, Replayed: true}
			return nil
		}
		out = Receipt{Report: rep}
		return tx.Audit(ctx, audit.Event{Actor: o.Actor, EntityType: EntityOccurrence, EntityID: rep.ID,
			EventType: audit.EventOccurrenceReceived, Payload: map[string]any{
				"origin": origin, "channel": rep.Channel, "category": rep.Category, "within_72h": rep.Within72h,
				"report_deadline_s": rep.DeadlineS, "received_at": stamp(rep.ReceivedAt), "became_aware_at": stamp(rep.BecameAwareAt),
				"has_reporter_person": len(rep.PersonSealed) > 0, "channel_overridden": overridden,
				"aircraft": len(rep.Aircraft), "manned": len(rep.Manned), "evidence_urls": len(rep.EvidenceURLs),
			}})
	})
	if err != nil {
		return Receipt{}, err
	}
	if out.Replayed {
		s.inc(CounterReplayed)
		return out, nil
	}
	s.inc(CounterReceived)
	if !out.Report.Within72h {
		s.inc(CounterLate)
	}
	return out, nil
}

// Get is one report.
func (s *Service) Get(ctx context.Context, id string) (Report, error) { return s.Store.Get(ctx, id) }

// List is one page of reports.
func (s *Service) List(ctx context.Context, f Filter) ([]Report, error) { return s.Store.List(ctx, f) }

// ReporterView is a report's reporter, for incident officers only.
type ReporterView struct {
	OccurrenceID string
	ReporterOrg  string
	ReportRef    string
	PersonRef    string
	HasPerson    bool
}

// Reporter opens the reporter of report id for actor, with purpose
// (required, at most MaxPurposeBytes, no control character). The read
// is an occurrence_reporter_viewed events row, committed before the
// identity is returned (376/2014 Art. 16(1)).
func (s *Service) Reporter(ctx context.Context, actor audit.Actor, id, purpose string) (ReporterView, error) {
	purpose = strings.TrimSpace(purpose)
	if purpose == "" {
		return ReporterView{}, core.Fieldf("purpose", "required: a reporter identity is read for a stated purpose")
	}
	var pe fieldErrs
	if text(&pe, "purpose", purpose, MaxPurposeBytes, false); pe.err() != nil {
		return ReporterView{}, pe.err()
	}
	var v ReporterView
	err := s.tx(ctx, func(tx Tx) error {
		r, err := tx.Get(ctx, id)
		if err != nil {
			return err
		}
		v = ReporterView{OccurrenceID: r.ID, ReporterOrg: r.ReporterOrg, ReportRef: r.ReportRef, HasPerson: len(r.PersonSealed) > 0}
		if v.HasPerson {
			if s.Sealer == nil {
				s.inc(CounterKeyUnavailable)
				return httpx.Refuse(http.StatusServiceUnavailable, SlugKeyUnavailable,
					"the reporter reference is sealed and OCCURRENCE_KEY_FILE is not configured on this instance")
			}
			p, err := s.Sealer.Open(r.PersonKeyID, r.PersonSealed, []byte(r.ID))
			if err != nil {
				s.inc(CounterReporterUnopened)
				return httpx.Refuse(http.StatusInternalServerError, SlugReporterUnknown,
					"the reporter reference does not open under the configured occurrence key (another key id or a changed row)")
			}
			v.PersonRef = string(p)
		}
		return tx.Audit(ctx, audit.Event{Actor: actor, Purpose: purpose, EntityType: EntityOccurrence, EntityID: r.ID,
			EventType: audit.EventOccurrenceReporterViewed, Payload: map[string]any{"has_reporter_person": v.HasPerson}})
	})
	if err != nil {
		return ReporterView{}, err
	}
	s.inc(CounterReporterViewed)
	return v, nil
}

// Classify records the safety risk class of report id (376/2014 Art.
// 7(2)) from the configured scheme.
func (s *Service) Classify(ctx context.Context, actor audit.Actor, id, class string) (Report, error) {
	class = strings.TrimSpace(class)
	if !slices.Contains(s.RiskClasses, class) {
		return Report{}, core.Fieldf("risk_classification", "is not a class of the configured scheme (%s)", strings.Join(s.RiskClasses, ", "))
	}
	var out Report
	err := s.tx(ctx, func(tx Tx) error {
		r, err := tx.GetForUpdate(ctx, id)
		if err != nil {
			return err
		}
		if r.State == StateClosed {
			return httpx.Refuse(http.StatusConflict, SlugClosed, "a closed occurrence report is not changed")
		}
		if out, err = tx.Classify(ctx, id, class, actor.ID); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{Actor: actor, EntityType: EntityOccurrence, EntityID: id, EventType: audit.EventOccurrenceClassified,
			Payload: map[string]any{"from": optional(r.RiskClassification), "to": class, "state_from": r.State, "state_to": out.State,
				"scheme": s.RiskClasses}})
	})
	if err != nil {
		return Report{}, err
	}
	s.inc(CounterClassified)
	return out, nil
}

func optional(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AnalysisPatch changes a report's analysis; nil members are kept.
type AnalysisPatch struct {
	Analysis *string
	FollowUp *string
	State    *string
}

// UpdateAnalysis applies p to report id: the analysis and follow-up, and
// the move to analysed (a classified report with an analysis) or closed
// (an analysed one). One occurrence_analysis_updated events row names
// what changed, never the text.
func (s *Service) UpdateAnalysis(ctx context.Context, actor audit.Actor, id string, p AnalysisPatch) (Report, error) {
	var e fieldErrs
	if p.Analysis == nil && p.FollowUp == nil && p.State == nil {
		e.add("body", "names nothing to change (analysis, follow_up, state)")
	}
	if p.Analysis != nil {
		text(&e, "analysis", *p.Analysis, MaxAnalysisBytes, true)
	}
	if p.FollowUp != nil {
		text(&e, "follow_up", *p.FollowUp, MaxAnalysisBytes, true)
	}
	if p.State != nil && *p.State != StateAnalysed && *p.State != StateClosed {
		e.add("state", "is not analysed or closed")
	}
	if err := e.err(); err != nil {
		return Report{}, err
	}
	var out Report
	err := s.tx(ctx, func(tx Tx) error {
		r, err := tx.GetForUpdate(ctx, id)
		if err != nil {
			return err
		}
		if r.State == StateClosed {
			return httpx.Refuse(http.StatusConflict, SlugClosed, "a closed occurrence report is not changed")
		}
		analysis, followUp, state := r.Analysis, r.FollowUp, r.State
		var changed []string
		if p.Analysis != nil && *p.Analysis != analysis {
			analysis = *p.Analysis
			changed = append(changed, "analysis")
		}
		if p.FollowUp != nil && *p.FollowUp != followUp {
			followUp = *p.FollowUp
			changed = append(changed, "follow_up")
		}
		if p.State != nil && *p.State != state {
			switch *p.State {
			case StateAnalysed:
				if r.State == StateReceived {
					return httpx.Refuse(http.StatusConflict, SlugNotClassified, "a report is classified before it is analysed (376/2014 Art. 7(2))")
				}
				if strings.TrimSpace(analysis) == "" {
					return core.Fieldf("analysis", "required to mark the report analysed")
				}
			case StateClosed:
				if r.State != StateAnalysed {
					return httpx.Refuse(http.StatusConflict, SlugNotAnalysed, "a report is analysed before it is closed")
				}
			}
			state = *p.State
			changed = append(changed, "state")
		}
		if len(changed) == 0 {
			out = r
			return nil
		}
		if out, err = tx.UpdateAnalysis(ctx, id, analysis, followUp, state, actor.ID); err != nil {
			return err
		}
		return tx.Audit(ctx, audit.Event{Actor: actor, EntityType: EntityOccurrence, EntityID: id, EventType: audit.EventOccurrenceAnalysisUpdated,
			Payload: map[string]any{"changed": changed, "state_from": r.State, "state_to": state}})
	})
	if err != nil {
		return Report{}, err
	}
	s.inc(CounterAnalysed)
	return out, nil
}

// ExportRequest is the window and format of an export.
type ExportRequest struct {
	From, To time.Time
	Format   string
}

// ExportResult is a sealed export: Content is the exact document whose
// SHA-256 is Export.ContentHash.
type ExportResult struct {
	Export  Export
	Content []byte
}

// Export builds the de-identified record set of the reports received in
// [From, To) in the requested format, seals it by its SHA-256 and records
// it (deidentified_exports and an occurrence_export_created events row)
// in one transaction. A window holding more than MaxExportRecords is
// refused, never thinned.
func (s *Service) Export(ctx context.Context, actor audit.Actor, req ExportRequest) (ExportResult, error) {
	format := strings.TrimSpace(req.Format)
	if format == "" {
		format = s.DefaultFormat
	}
	ex, ok := s.Exporters[format]
	if !ok {
		return ExportResult{}, httpx.Refuse(http.StatusBadRequest, SlugUnknownFormat, "this build exports "+strings.Join(s.Exporters.Formats(), ", "),
			core.Fieldf("format", "is not a format of this build (%s)", strings.Join(s.Exporters.Formats(), ", ")))
	}
	if req.From.IsZero() || req.To.IsZero() || !req.To.After(req.From) {
		return ExportResult{}, core.Fieldf("to", "must be after from")
	}
	from, to := req.From.UTC(), req.To.UTC()
	limit := s.MaxExportRecords
	if limit <= 0 {
		return ExportResult{}, errors.New("occurrences: no export bound configured (OCCURRENCES_EXPORT_MAX_RECORDS)")
	}
	var out ExportResult
	err := s.tx(ctx, func(tx Tx) error {
		now, err := tx.Now(ctx)
		if err != nil {
			return err
		}
		rows, err := tx.Received(ctx, from, to, limit+1)
		if err != nil {
			return err
		}
		if len(rows) > limit {
			s.inc(CounterExportTooLarge)
			return httpx.Refuse(http.StatusBadRequest, SlugExportTooLarge, "the window holds more reports than one export may; narrow it",
				core.Fieldf("to", "the window holds more than %d reports (OCCURRENCES_EXPORT_MAX_RECORDS)", limit))
		}
		meta := ExportMeta{ExportID: s.newID(), CreatedAt: now, From: from, To: to}
		content, err := ex.Export(meta, rows)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		e := Export{ID: meta.ExportID, CreatedAt: now, CreatedBy: actor.ID, Format: ex.Format(), ContentHash: "sha256:" + hex.EncodeToString(sum[:]),
			SizeBytes: int64(len(content)), RecordCount: len(rows), From: from, To: to}
		if err := tx.InsertExport(ctx, &e); err != nil {
			return err
		}
		out = ExportResult{Export: e, Content: content}
		return tx.Audit(ctx, audit.Event{Actor: actor, EntityType: EntityExport, EntityID: e.ID, EventType: audit.EventOccurrenceExportCreated,
			Payload: map[string]any{"format": e.Format, "content_hash": e.ContentHash, "size_bytes": e.SizeBytes,
				"record_count": e.RecordCount, "from": stamp(from), "to": stamp(to)}})
	})
	if err != nil {
		return ExportResult{}, err
	}
	s.inc(CounterExports)
	return out, nil
}
