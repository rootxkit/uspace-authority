package incidents

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the case files (E-09).
const (
	CounterOpened              = "incidents_opened"
	CounterOpenedFromViolation = "incidents_opened_from_violation"
	CounterUpdated             = "incidents_updated"
	CounterBackfilled          = "incidents_backfilled" // opened for an escalation recorded before this build
	CounterBackfillFailed      = "incidents_backfill_failed"
	CounterBoundRefused        = "incidents_bound_refused" // an aircraft or a note past the bound (E-10)
)

// EntityType names an incident (and its packs) in events.
const EntityType = "incident"

// SlugIncidentFull refuses an aircraft or a note past the bound.
const SlugIncidentFull = "incident_full"

// Service holds the case files (api only).
type Service struct {
	DB    *pg.DB
	Audit *audit.Writer
	// PublicPart keeps an operator registration's public part only; nil
	// keeps the value trimmed (tests).
	PublicPart PublicPartFunc
	// WriteTimeout bounds one transaction.
	WriteTimeout time.Duration
	Counters     *core.Counters
	Logger       *slog.Logger
	// NewID numbers an incident; nil is bus.NewULID.
	NewID func(time.Time) string
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return logging.Discard()
}

// warn is the rate-limited logger of key when lim is set (E-09).
func (s *Service) warn(lim *logging.Limiter, key string) *slog.Logger {
	if lim != nil {
		return lim.Limited(key)
	}
	return s.logger()
}

func (s *Service) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) newID() string {
	if s.NewID != nil {
		return s.NewID(time.Now())
	}
	return bus.NewULID(time.Now())
}

func (s *Service) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.WriteTimeout > 0 {
		return context.WithTimeout(ctx, s.WriteTimeout)
	}
	return context.WithCancel(ctx)
}

func notFound(id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such incident",
		core.Fieldf("incident_id", "%q is not an incident", id))
}

// View is one incident with what it holds.
type View struct {
	Incident gen.Incident
	Aircraft []gen.ListIncidentAircraftRow
	Notes    []gen.ListIncidentNotesRow
	Packs    []gen.ListEvidencePacksRow
}

func (s *Service) insertAircraft(ctx context.Context, q *gen.Queries, id, by string, list []Aircraft) error {
	for _, a := range list {
		ident, err := json.Marshal(a.Identification)
		if err != nil {
			return err
		}
		tracks := a.TrackIDs
		if tracks == nil {
			tracks = []string{}
		}
		if err := q.InsertIncidentAircraft(ctx, gen.InsertIncidentAircraftParams{IncidentID: id, Serial: a.Serial,
			OperatorReg: a.OperatorReg, RegistryUasID: a.RegistryUASID, TrackIds: tracks, Identification: ident, AddedBy: by}); err != nil {
			return err
		}
	}
	return nil
}

func aircraftPayload(list []Aircraft) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]any{"serial": a.Serial, "operator_reg": a.OperatorReg, "track_ids": a.TrackIDs})
	}
	return out
}

// Open opens an incident from the authority's own observation or a
// notice, with its events row, in one transaction.
func (s *Service) Open(ctx context.Context, actor audit.Actor, in NewIncident) (View, error) {
	return s.open(ctx, actor, in, false)
}

// PoliceRequest is a police export of an area and a window (WP-19): the
// agency, its case reference, when, and the aircraft the picture held.
type PoliceRequest struct {
	Agency     string
	CaseRef    string
	OccurredAt time.Time
	Narrative  string
	Aircraft   []Aircraft
}

// OpenForPolice opens the authority's case file of a police export
// (opened_from police_request, kind other, severity info): the pack's
// chain of custody starts at an incident like every other pack's. The
// notice reference names the agency and the case.
func (s *Service) OpenForPolice(ctx context.Context, actor audit.Actor, r PoliceRequest) (View, error) {
	ref := r.Agency + ": " + r.CaseRef
	if len(ref) > MaxNoticeRefLen {
		ref = ref[:MaxNoticeRefLen]
		for !utf8.ValidString(ref) {
			ref = ref[:len(ref)-1]
		}
	}
	return s.open(ctx, actor, NewIncident{Kind: KindOther, OccurredAt: r.OccurredAt, OpenedFrom: FromPoliceRequest, NoticeRef: &ref,
		Severity: string(core.SeverityInfo), Narrative: r.Narrative, Aircraft: r.Aircraft}, true)
}

func (s *Service) open(ctx context.Context, actor audit.Actor, in NewIncident, viaPolice bool) (View, error) {
	if err := checkNew(&in, s.PublicPart, viaPolice); err != nil {
		return View{}, err
	}
	refs := in.IntentRefs
	if refs == nil {
		refs = []string{}
	}
	id := s.newID()
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if _, err := q.InsertIncident(ctx, gen.InsertIncidentParams{IncidentID: id, Kind: in.Kind, OccurredAt: in.OccurredAt,
			OpenedFrom: in.OpenedFrom, NoticeRef: in.NoticeRef, IntentRefs: refs, Narrative: in.Narrative, Severity: in.Severity,
			OpenedBy: actor.ID}); err != nil {
			return err
		}
		if err := s.insertAircraft(ctx, q, id, actor.ID, in.Aircraft); err != nil {
			return err
		}
		_, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityType, EntityID: id,
			EventType: audit.EventIncidentOpened, Payload: map[string]any{
				"kind": in.Kind, "opened_from": in.OpenedFrom, "notice_ref": in.NoticeRef, "severity": in.Severity,
				"occurred_at": bus.Stamp(in.OccurredAt), "intent_refs": refs, "aircraft": aircraftPayload(in.Aircraft),
				"narrative": in.Narrative,
			}})
		return err
	})
	if err != nil {
		return View{}, err
	}
	s.inc(CounterOpened)
	return s.Get(ctx, id)
}

// trackRefs are a violation's track ids, its own first, unique, at most
// MaxTrackIDs.
func trackRefs(v *gen.GetViolationForUpdateRow) []string {
	out := []string{v.TrackID}
	for _, t := range v.EvidenceTrackIds {
		if len(out) == MaxTrackIDs {
			break
		}
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// OpenFromViolation opens the incident of an escalated violation inside
// the caller's transaction q, which holds the violation row locked (FOR
// UPDATE), so two escalations or two replicas cannot open two. It is
// idempotent: an incident already opened from the violation is
// returned. The aircraft is what identified it at detection: the
// serial, the registration's public part, the registry's id and the
// track ids, with the evidence trust.
func (s *Service) OpenFromViolation(ctx context.Context, q *gen.Queries, actor audit.Actor, v *gen.GetViolationForUpdateRow) (string, error) {
	if existing, err := q.IncidentForViolation(ctx, &v.ViolationID); err == nil {
		return existing, nil
	} else if !store.IsNoRows(err) {
		return "", err
	}
	a := Aircraft{Serial: nonEmpty(v.Serial), OperatorReg: nonEmpty(v.OperatorReg), RegistryUASID: nonEmpty(v.RegistryUasID),
		TrackIDs: trackRefs(v), Identification: Identification{EvidenceTrust: v.EvidenceTrust}}
	a, err := normaliseAircraft("aircraft", a, s.PublicPart)
	if err != nil {
		return "", err
	}
	id := s.newID()
	narrative := ""
	if v.ReviewNote != nil {
		narrative = *v.ReviewNote
	}
	if _, err := q.InsertIncident(ctx, gen.InsertIncidentParams{IncidentID: id, Kind: KindViolationEscalated, OccurredAt: v.OpenedAt,
		OpenedFrom: FromViolation, SourceViolationID: &v.ViolationID, IntentRefs: []string{}, Narrative: narrative,
		Severity: v.Severity, OpenedBy: actor.ID}); err != nil {
		return "", err
	}
	if err := s.insertAircraft(ctx, q, id, actor.ID, []Aircraft{a}); err != nil {
		return "", err
	}
	if _, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityType, EntityID: id,
		EventType: audit.EventIncidentOpened, Payload: map[string]any{
			"kind": KindViolationEscalated, "opened_from": FromViolation, "source_violation_id": v.ViolationID,
			"violation_kind": v.Kind, "severity": v.Severity, "occurred_at": bus.Stamp(v.OpenedAt),
			"aircraft": aircraftPayload([]Aircraft{a}), "escalated_by": v.ReviewedBy,
		}}); err != nil {
		return "", err
	}
	s.inc(CounterOpened)
	s.inc(CounterOpenedFromViolation)
	return id, nil
}

func nonEmpty(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

// actorBackfill opens the incidents of escalations recorded before this
// build (incident_requested without an incident).
var actorBackfill = audit.SystemActor("incidents")

// OpenRequested opens, at most limit at a time, an incident for every
// escalated violation that has none (escalations recorded before the
// incidents existed, WP-12's incident_requested), each in its own
// transaction. It returns how many it opened.
func (s *Service) OpenRequested(ctx context.Context, limit int) (int, error) {
	ids, err := s.DB.Queries().RequestedIncidentsWithoutIncident(ctx, int32(limit))
	if err != nil {
		return 0, err
	}
	n := 0
	for _, vid := range ids {
		tctx, cancel := s.bounded(ctx)
		err := s.DB.WithTx(tctx, func(q *gen.Queries) error {
			v, err := q.GetViolationForUpdate(tctx, vid)
			if err != nil {
				return err
			}
			_, err = s.OpenFromViolation(tctx, q, actorBackfill, &v)
			return err
		})
		cancel()
		if err != nil {
			s.inc(CounterBackfillFailed)
			return n, err
		}
		n++
		s.inc(CounterBackfilled)
	}
	return n, nil
}

// RunBackfill runs OpenRequested now and every period until ctx ends; a
// failure is logged and retried at the next period.
func (s *Service) RunBackfill(ctx context.Context, period time.Duration, limit int, lim *logging.Limiter) {
	t := time.NewTicker(period)
	defer t.Stop()
	for {
		if n, err := s.OpenRequested(ctx, limit); err != nil && ctx.Err() == nil {
			s.warn(lim, "incidents_backfill").Warn("incidents for earlier escalations not opened yet; retried",
				slog.String("error", err.Error()))
		} else if n > 0 {
			s.logger().Info("incidents opened for earlier escalations", slog.Int("count", n))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Get reads one incident with its aircraft, notes and packs.
func (s *Service) Get(ctx context.Context, id string) (View, error) {
	q := s.DB.Queries()
	inc, err := q.GetIncident(ctx, id)
	if store.IsNoRows(err) {
		return View{}, notFound(id)
	}
	if err != nil {
		return View{}, err
	}
	v := View{Incident: inc}
	if v.Aircraft, err = q.ListIncidentAircraft(ctx, id); err != nil {
		return View{}, err
	}
	if v.Notes, err = q.ListIncidentNotes(ctx, id); err != nil {
		return View{}, err
	}
	if v.Packs, err = q.ListEvidencePacks(ctx, id); err != nil {
		return View{}, err
	}
	return v, nil
}

// List reads one page.
func (s *Service) List(ctx context.Context, p gen.ListIncidentsParams) ([]gen.ListIncidentsRow, error) {
	return s.DB.Queries().ListIncidents(ctx, p)
}

func full(what string, n int) error {
	return httpx.Refuse(http.StatusConflict, SlugIncidentFull, "an incident holds at most "+strconv.Itoa(n)+" "+what,
		core.Fieldf(what, "at most %d per incident", n))
}

// Update applies p in one transaction with one incident_updated events
// row naming every change (from and to).
func (s *Service) Update(ctx context.Context, actor audit.Actor, id string, p Patch) (View, error) {
	if err := s.checkPatch(&p); err != nil {
		return View{}, err
	}
	ctx, cancel := s.bounded(ctx)
	defer cancel()
	changed := false
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		cur, err := q.GetIncidentForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFound(id)
		}
		if err != nil {
			return err
		}
		next := gen.UpdateIncidentParams{IncidentID: id, Narrative: cur.Narrative, Severity: cur.Severity, Status: cur.Status,
			Assignee: cur.Assignee, IntentRefs: cur.IntentRefs}
		changes := map[string]any{}
		if p.Narrative != nil && *p.Narrative != cur.Narrative {
			changes["narrative"] = map[string]any{"from": cur.Narrative, "to": *p.Narrative}
			next.Narrative = *p.Narrative
		}
		if p.Severity != nil && *p.Severity != cur.Severity {
			changes["severity"] = map[string]any{"from": cur.Severity, "to": *p.Severity}
			next.Severity = *p.Severity
		}
		if p.Assignee != nil && (cur.Assignee == nil || *cur.Assignee != *p.Assignee) {
			changes["assignee"] = map[string]any{"from": cur.Assignee, "to": *p.Assignee}
			next.Assignee = p.Assignee
		}
		if p.Status != nil && *p.Status != cur.Status {
			if err := checkStatus(*p.Status, next.Assignee); err != nil {
				return err
			}
			changes["status"] = map[string]any{"from": cur.Status, "to": *p.Status}
			next.Status = *p.Status
		}
		if p.IntentRefs != nil && !slices.Equal(*p.IntentRefs, cur.IntentRefs) {
			changes["intent_refs"] = map[string]any{"from": cur.IntentRefs, "to": *p.IntentRefs}
			next.IntentRefs = *p.IntentRefs
		}
		if len(p.AddAircraft) > 0 {
			n, err := q.CountIncidentAircraft(ctx, id)
			if err != nil {
				return err
			}
			if int(n)+len(p.AddAircraft) > MaxAircraft {
				s.inc(CounterBoundRefused)
				return full("aircraft", MaxAircraft)
			}
			if err := s.insertAircraft(ctx, q, id, actor.ID, p.AddAircraft); err != nil {
				return err
			}
			changes["aircraft_added"] = aircraftPayload(p.AddAircraft)
		}
		if p.Note != nil {
			n, err := q.CountIncidentNotes(ctx, id)
			if err != nil {
				return err
			}
			if int(n) >= MaxNotes {
				s.inc(CounterBoundRefused)
				return full("notes", MaxNotes)
			}
			note, err := q.InsertIncidentNote(ctx, gen.InsertIncidentNoteParams{IncidentID: id, Author: actor.ID, Body: *p.Note})
			if err != nil {
				return err
			}
			changes["note_added"] = map[string]any{"note_id": note.ID, "body": *p.Note}
		}
		if len(changes) == 0 {
			return nil
		}
		changed = true
		if _, err := q.UpdateIncident(ctx, next); err != nil {
			return err
		}
		_, err = s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: EntityType, EntityID: id,
			EventType: audit.EventIncidentUpdated, Payload: map[string]any{"changes": changes}})
		return err
	})
	if err != nil {
		return View{}, err
	}
	if changed {
		s.inc(CounterUpdated)
	}
	return s.Get(ctx, id)
}

func (s *Service) checkPatch(p *Patch) error {
	if p.Narrative != nil {
		if err := textLen("narrative", *p.Narrative, MaxNarrative); err != nil {
			return err
		}
	}
	if p.Severity != nil {
		if err := oneOf("severity", *p.Severity, severities); err != nil {
			return err
		}
	}
	if p.Status != nil {
		if err := oneOf("status", *p.Status, statuses); err != nil {
			return err
		}
	}
	if p.Assignee != nil && (*p.Assignee == "" || len(*p.Assignee) > 128) {
		return core.Fieldf("assignee", "1 to 128 characters")
	}
	if p.IntentRefs != nil {
		if err := checkRefs("intent_refs", *p.IntentRefs, MaxIntentRefs); err != nil {
			return err
		}
	}
	if p.Note != nil {
		if *p.Note == "" {
			return core.Fieldf("note", "empty")
		}
		if err := textLen("note", *p.Note, MaxNote); err != nil {
			return err
		}
	}
	if len(p.AddAircraft) > MaxAircraft {
		return core.Fieldf("add_aircraft", "at most %d", MaxAircraft)
	}
	for i := range p.AddAircraft {
		a, err := normaliseAircraft(fieldIndex("add_aircraft", i), p.AddAircraft[i], s.PublicPart)
		if err != nil {
			return err
		}
		p.AddAircraft[i] = a
	}
	return nil
}
