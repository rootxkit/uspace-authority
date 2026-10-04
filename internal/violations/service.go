package violations

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	apigen "github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/violation"
)

// Counters of the component (E-09).
const (
	CounterApplied          = "violation_messages_applied"   // a message changed a row
	CounterInserted         = "violations_inserted"          // a new row (a raise, or an update of an unknown id: a raise lost on the way)
	CounterDuplicate        = "violation_messages_duplicate" // a redelivered raise of a known id: nothing written
	CounterAfterClose       = "violation_messages_after_close"
	CounterMalformed        = "violation_messages_malformed" // a message that does not decode or validate: terminated, logged
	CounterApplyFailed      = "violation_apply_failed"       // a write failed: redelivered after a delay
	CounterExcerptTruncated = "violation_excerpt_truncated"  // samples past the stored bound left out (E-10)
	CounterClosedSilent     = "violations_closed_detector_silent"
	CounterReviewed         = "violations_reviewed"
	// CounterRevived counts violations closed detector_silent that a later
	// update brought back (detect never stopped holding them).
	CounterRevived = "violations_revived"
)

// ClearReasonDetectorSilent closes a violation detect has stopped
// republishing (a detect restart: its monitor no longer holds it). It is
// not a judgement of the aircraft.
const ClearReasonDetectorSilent = "detector_silent"

// actorDetect is the system actor of what detect reports.
var actorDetect = audit.SystemActor("detect")

// entityType names a violation in events.
const entityType = "violation"

// Service persists violations and reviews them (api only).
type Service struct {
	DB    *pg.DB
	Audit *audit.Writer
	// MaxExcerptSamples bounds the samples stored per violation (E-10).
	MaxExcerptSamples int
	// WriteTimeout bounds one transaction.
	WriteTimeout time.Duration
	Counters     *core.Counters
	Logger       *slog.Logger
	// OnEscalate opens the incident of an escalated violation inside the
	// review's transaction, the violation row locked (WP-17:
	// incidents.Service.OpenFromViolation). Nil leaves the request
	// (incident_requested) for incidents' backfill job.
	OnEscalate func(ctx context.Context, q *gen.Queries, actor audit.Actor, v *gen.GetViolationForUpdateRow) (string, error)
	// CutExcerpt cuts an excerpt into segments and holes by the evidence
	// packs' rule for the console (WP-17's incidents.ExcerptCutter, B-13);
	// read after the violation's row, never inside a transaction. Nil:
	// GET answers the segmenting unavailable, and the console draws the
	// samples unjoined.
	CutExcerpt func(ctx context.Context, excerpt []map[string]any) apigen.ViolationExcerptSegmenting
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return logging.Discard()
}

func (s *Service) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.WriteTimeout > 0 {
		return context.WithTimeout(ctx, s.WriteTimeout)
	}
	return context.WithCancel(ctx)
}

// Outcome is what Apply did with a message.
type Outcome string

// The outcomes.
const (
	OutcomeInserted   Outcome = "inserted"
	OutcomeUpdated    Outcome = "updated"
	OutcomeDuplicate  Outcome = "duplicate"
	OutcomeAfterClose Outcome = "after_close"
	// OutcomeRevived: an update of a violation closed detector_silent,
	// carrying evidence newer than the close; it is open again.
	OutcomeRevived Outcome = "revived"
)

func parseTime(field, s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, core.Fieldf(field, "%q is not a time", s)
	}
	return t, nil
}

func parseTimePtr(field string, s *string) (*time.Time, error) {
	if s == nil {
		return nil, nil
	}
	t, err := parseTime(field, *s)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func jsonOf(v any) ([]byte, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

// mergeExcerpt appends add to held up to max samples; truncated says
// samples were left out.
func mergeExcerpt(held []json.RawMessage, add []violation.Sample, maxSamples int) (out []json.RawMessage, truncated bool, err error) {
	out = held
	for i := range add {
		if maxSamples > 0 && len(out) >= maxSamples {
			return out, true, nil
		}
		raw, err := json.Marshal(&add[i])
		if err != nil {
			return nil, false, err
		}
		out = append(out, raw)
	}
	return out, false, nil
}

// trackIDs are the track ids among refs.
func trackIDs(refs []violation.EvidenceRef) []string {
	out := []string{}
	for _, r := range refs {
		if r.Type == violation.RefTrack {
			out = append(out, r.ID)
		}
	}
	return out
}

// Apply applies one violation/v1 message in one transaction, idempotent
// on violation_id (JetStream redelivers): a raise of an unknown id
// inserts it; an update or a clear of an unknown id inserts it too (a
// raise lost on the way, never a hole); a raise of a known id writes
// nothing; an update refreshes the numbers and appends the samples up
// to the bound; a clear closes it. Nothing reopens a violation detect
// cleared; one api closed detector_silent is revived by an update or a
// clear carrying evidence newer than what it held (detect never stopped
// holding it: its republication was lost, e.g. in a bus outage), as one
// continuous violation with the silent gap audited (violation_revived).
// Every transition (raised, revived, severity changed, cleared) is an
// events row in the same transaction. A message that cannot be stored is an error
// naming the field.
func (s *Service) Apply(ctx context.Context, m *violation.Message) (Outcome, error) {
	b := &m.Body
	captured, err := parseTime("body.captured_at", b.CapturedAt)
	if err != nil {
		return "", err
	}
	opened, err := parseTime("body.opened_at", b.OpenedAt)
	if err != nil {
		return "", err
	}
	closed, err := parseTimePtr("body.closed_at", b.ClosedAt)
	if err != nil {
		return "", err
	}
	detail, err := json.Marshal(b.Detail)
	if err != nil {
		return "", err
	}
	clearing, err := jsonOf(mapOrNil(b.ClearingDetail))
	if err != nil {
		return "", err
	}
	var peakName *string
	var peakValue *float64
	if b.Peak != nil && core.IsFinite(b.Peak.Value) {
		peakName, peakValue = &b.Peak.Name, &b.Peak.Value
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var outcome Outcome
	var truncated bool
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		row, err := q.GetViolationForUpdate(ctx, b.ViolationID)
		if store.IsNoRows(err) {
			outcome = OutcomeInserted
			var t bool
			t, err = s.insert(ctx, q, m, captured, opened, closed, detail, clearing, peakName, peakValue)
			truncated = t
			return err
		}
		if err != nil {
			return err
		}
		revived := false
		switch {
		case row.ClosedAt != nil && revivable(&row, b.State, captured):
			revived = true
		case row.ClosedAt != nil:
			outcome = OutcomeAfterClose
			return nil
		case b.State == violation.StateRaised:
			outcome = OutcomeDuplicate
			return nil
		}
		outcome = OutcomeUpdated
		if revived {
			outcome = OutcomeRevived
			if err := s.record(ctx, q, b, audit.EventViolationRevived, map[string]any{
				"closed_as": ClearReasonDetectorSilent, "closed_at": bus.Stamp(*row.ClosedAt),
				"silent_from": bus.Stamp(row.LastCapturedAt), "resumed_at": b.CapturedAt,
				"silent_for_s": captured.Sub(row.LastCapturedAt).Seconds(), "continuous": true, "as_state": b.State,
			}); err != nil {
				return err
			}
		}
		// The stored excerpt is rewritten only when samples are added
		// (a republication every second usually carries none).
		excerpt, samples, t := row.EvidenceExcerpt, int(row.ExcerptSamples), false
		if len(b.EvidenceExcerpt) > 0 {
			var held []json.RawMessage
			if err := json.Unmarshal(row.EvidenceExcerpt, &held); err != nil {
				return fmt.Errorf("stored excerpt: %w", err)
			}
			merged, mt, err := mergeExcerpt(held, b.EvidenceExcerpt, s.MaxExcerptSamples)
			if err != nil {
				return err
			}
			if excerpt, err = json.Marshal(merged); err != nil {
				return err
			}
			samples, t = len(merged), mt
		}
		truncated = t
		if peakValue == nil {
			peakName, peakValue = row.PeakName, row.PeakValue
		}
		if b.State == violation.StateCleared && closed == nil {
			return &core.FieldError{Field: "body.closed_at", Reason: "required when cleared"}
		}
		err = q.UpdateViolation(ctx, gen.UpdateViolationParams{
			ViolationID: b.ViolationID, Severity: string(b.Severity), DetectorState: string(b.State), ClosedAt: closed,
			ClearReason: b.ClearReason, LastCapturedAt: captured, PolicyVersion: b.PolicyVersion, PeakName: peakName,
			PeakValue: peakValue, Detail: detail, ClearingDetail: clearing, InUspace: b.InUSpace, EvidenceExcerpt: excerpt,
			ExcerptSamples: int32(samples), ExcerptTruncated: row.ExcerptTruncated || t,
		})
		if err != nil {
			return err
		}
		if row.Severity != string(b.Severity) {
			if err := s.record(ctx, q, b, audit.EventViolationSeverityChanged, map[string]any{
				"from": row.Severity, "to": b.Severity, "policy_version": b.PolicyVersion, "captured_at": b.CapturedAt,
			}); err != nil {
				return err
			}
		}
		if b.State == violation.StateCleared {
			return s.recordCleared(ctx, q, b)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	s.count(outcome, truncated)
	return outcome, nil
}

// revivable reports whether a message for a closed row brings it back:
// only a row api closed detector_silent, only by an update or a clear
// (a raise of a known id is a redelivery), and only with evidence placed
// after the newest the row held (a redelivered older message is not).
func revivable(row *gen.GetViolationForUpdateRow, state violation.State, captured time.Time) bool {
	return row.ClearReason != nil && *row.ClearReason == ClearReasonDetectorSilent &&
		state != violation.StateRaised && captured.After(row.LastCapturedAt)
}

func mapOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}

func (s *Service) count(o Outcome, truncated bool) {
	if s.Counters == nil {
		return
	}
	switch o {
	case OutcomeInserted:
		s.Counters.Inc(CounterInserted)
		s.Counters.Inc(CounterApplied)
	case OutcomeUpdated:
		s.Counters.Inc(CounterApplied)
	case OutcomeRevived:
		s.Counters.Inc(CounterRevived)
		s.Counters.Inc(CounterApplied)
	case OutcomeDuplicate:
		s.Counters.Inc(CounterDuplicate)
	case OutcomeAfterClose:
		s.Counters.Inc(CounterAfterClose)
	}
	if truncated {
		s.Counters.Inc(CounterExcerptTruncated)
	}
}

func (s *Service) insert(ctx context.Context, q *gen.Queries, m *violation.Message, captured, opened time.Time, closed *time.Time,
	detail, clearing []byte, peakName *string, peakValue *float64) (bool, error) {
	b := &m.Body
	merged, truncated, err := mergeExcerpt(nil, b.EvidenceExcerpt, s.MaxExcerptSamples)
	if err != nil {
		return false, err
	}
	if merged == nil {
		merged = []json.RawMessage{}
	}
	excerpt, err := json.Marshal(merged)
	if err != nil {
		return false, err
	}
	refs := b.EvidenceRefs
	if refs == nil {
		refs = []violation.EvidenceRef{}
	}
	refsJSON, err := json.Marshal(refs)
	if err != nil {
		return false, err
	}
	terrain, err := jsonOf(terrainOrNil(b.TerrainSource))
	if err != nil {
		return false, err
	}
	p := gen.InsertViolationParams{
		ViolationID: b.ViolationID, Kind: string(b.Kind), Severity: string(b.Severity), AlertKey: b.AlertKey, TrackID: b.TrackRef,
		Serial: b.Serial, OperatorReg: b.OperatorReg, RegistryUasID: b.RegistryUASID, ZoneID: b.ZoneID, ZoneVersion: b.ZoneVersion,
		ZoneType: b.ZoneType, DetectorState: string(b.State), OpenedAt: opened, ClosedAt: closed, ClearReason: b.ClearReason,
		LastCapturedAt: captured, PolicyVersion: b.PolicyVersion, PeakName: peakName, PeakValue: peakValue, Detail: detail,
		ClearingDetail: clearing, TerrainSource: terrain, InUspace: b.InUSpace, EvidenceTrust: string(b.EvidenceTrust),
		EvidenceRefs: refsJSON, EvidenceTrackIds: trackIDs(refs), EvidenceExcerpt: excerpt, ExcerptSamples: int32(len(merged)),
		ExcerptTruncated: truncated, Cell5: b.Cell5,
	}
	if len(b.EvidenceExcerpt) > 0 {
		lat, lon := b.EvidenceExcerpt[0].Lat, b.EvidenceExcerpt[0].Lng
		p.FirstLatDeg, p.FirstLonDeg = &lat, &lon
	}
	if b.State == violation.StateCleared && closed == nil {
		return false, &core.FieldError{Field: "body.closed_at", Reason: "required when cleared"}
	}
	if err := q.InsertViolation(ctx, p); err != nil {
		return false, err
	}
	payload := map[string]any{
		"kind": b.Kind, "severity": b.Severity, "track_ref": b.TrackRef, "alert_key": b.AlertKey, "zone_id": b.ZoneID,
		"opened_at": b.OpenedAt, "captured_at": b.CapturedAt, "policy_version": b.PolicyVersion,
		"evidence_trust": b.EvidenceTrust, "as_state": b.State,
	}
	if err := s.record(ctx, q, b, audit.EventViolationRaised, payload); err != nil {
		return false, err
	}
	if b.State == violation.StateCleared {
		if err := s.recordCleared(ctx, q, b); err != nil {
			return false, err
		}
	}
	return truncated, nil
}

func terrainOrNil(t *violation.TerrainSource) any {
	if t == nil {
		return nil
	}
	return t
}

func (s *Service) recordCleared(ctx context.Context, q *gen.Queries, b *violation.Body) error {
	payload := map[string]any{"clear_reason": b.ClearReason, "closed_at": b.ClosedAt, "policy_version": b.PolicyVersion}
	if b.Peak != nil {
		payload["peak"] = b.Peak
	}
	if b.ClearingDetail != nil {
		payload["clearing_detail"] = b.ClearingDetail
	}
	return s.record(ctx, q, b, audit.EventViolationCleared, payload)
}

func (s *Service) record(ctx context.Context, q *gen.Queries, b *violation.Body, eventType string, payload map[string]any) error {
	payload["kind"] = b.Kind
	_, err := s.Audit.Record(ctx, q, audit.Event{Actor: actorDetect, EntityType: entityType, EntityID: b.ViolationID,
		EventType: eventType, Payload: payload})
	return err
}

// CloseSilent closes, at most limit at a time, every open violation no
// message has touched for olderThan on the database's clock, as
// detector_silent, each with its events row. It returns how many.
func (s *Service) CloseSilent(ctx context.Context, olderThan time.Duration, limit int) (int, error) {
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	n := 0
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		rows, err := q.CloseSilentViolations(ctx, gen.CloseSilentViolationsParams{OlderThanS: olderThan.Seconds(), Lim: int32(limit)})
		if err != nil {
			return err
		}
		for _, r := range rows {
			if _, err := s.Audit.Record(ctx, q, audit.Event{Actor: audit.SystemActor("api"), EntityType: entityType,
				EntityID: r.ViolationID, EventType: audit.EventViolationCleared, Payload: map[string]any{
					"kind": r.Kind, "clear_reason": ClearReasonDetectorSilent, "silent_for_s": olderThan.Seconds(),
				}}); err != nil {
				return err
			}
		}
		n = len(rows)
		return nil
	})
	if err != nil {
		return 0, err
	}
	if n > 0 && s.Counters != nil {
		s.Counters.Add(CounterClosedSilent, uint64(n))
	}
	return n, nil
}

// Review decisions.
const (
	DecisionReviewed  = "reviewed"
	DecisionDismissed = "dismissed"
	DecisionEscalated = "escalated"
)

// SlugReviewed is the refusal of a review of a violation already
// dismissed or escalated.
const SlugReviewed = "violation_reviewed"

func notFound(id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such violation",
		core.Fieldf("violation_id", "%q is not a violation", id))
}

// Review records an inspector's decision in one transaction with its
// events row (06 §2 T1: broadcast-only evidence is never escalated
// without a note); escalation requests an incident and, through
// OnEscalate, opens it in the same transaction.
func (s *Service) Review(ctx context.Context, actor audit.Actor, id, decision string, note *string) (gen.GetViolationRow, error) {
	switch decision {
	case DecisionReviewed, DecisionDismissed, DecisionEscalated:
	default:
		return gen.GetViolationRow{}, core.Fieldf("decision", "%q is not reviewed, dismissed or escalated", decision)
	}
	if note != nil && *note == "" {
		note = nil
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	var out gen.GetViolationRow
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		row, err := q.GetViolationForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFound(id)
		}
		if err != nil {
			return err
		}
		if row.Status == DecisionDismissed || row.Status == DecisionEscalated {
			return httpx.Refuse(http.StatusConflict, SlugReviewed, "the violation was already "+row.Status,
				core.Fieldf("decision", "a %s violation is not reviewed again", row.Status))
		}
		if decision == DecisionEscalated && row.EvidenceTrust == string(core.TrustBroadcast) && note == nil {
			return &core.FieldError{Field: "note", Reason: "required to escalate broadcast-only evidence (06 §2 T1)"}
		}
		escalate := decision == DecisionEscalated
		if err := q.ReviewViolation(ctx, gen.ReviewViolationParams{ViolationID: id, Status: decision, ReviewedBy: &actor.ID,
			ReviewNote: note, IncidentRequested: escalate}); err != nil {
			return err
		}
		eventType := map[string]string{DecisionReviewed: audit.EventViolationReviewed, DecisionDismissed: audit.EventViolationDismissed,
			DecisionEscalated: audit.EventViolationEscalated}[decision]
		payload := map[string]any{"from": row.Status, "to": decision, "evidence_trust": row.EvidenceTrust, "kind": row.Kind}
		if note != nil {
			payload["note"] = *note
		}
		if _, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: entityType, EntityID: id, EventType: eventType,
			Payload: payload}); err != nil {
			return err
		}
		if escalate {
			// The request is recorded, and the incident opened from it in
			// this transaction (WP-17), so an escalation never commits
			// without its case file when the hook is wired.
			if _, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: entityType, EntityID: id,
				EventType: audit.EventIncidentRequested, Payload: map[string]any{"kind": row.Kind, "opened_from": "violation"}}); err != nil {
				return err
			}
			if s.OnEscalate != nil {
				row.Status, row.ReviewedBy, row.ReviewNote = decision, &actor.ID, note
				if _, err := s.OnEscalate(ctx, q, actor, &row); err != nil {
					return err
				}
			}
		}
		out, err = q.GetViolation(ctx, id)
		return err
	})
	if err == nil && s.Counters != nil {
		s.Counters.Inc(CounterReviewed)
	}
	return out, err
}

// Get reads one violation.
func (s *Service) Get(ctx context.Context, id string) (gen.GetViolationRow, error) {
	row, err := s.DB.Queries().GetViolation(ctx, id)
	if store.IsNoRows(err) {
		return row, notFound(id)
	}
	return row, err
}

// List reads one page.
func (s *Service) List(ctx context.Context, p gen.ListViolationsParams) ([]gen.ListViolationsRow, error) {
	return s.DB.Queries().ListViolations(ctx, p)
}
