package occurrences

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/pii"
)

// Test fixtures: GEO-TEST-* and FIN* registrations, TEST* serials
// (CLAUDE.md rule 11); keys are generated at test time.

// anspBody is the body the ANSP's outbox posts (uspace-ansp
// internal/coord MessageOf over its occurrenceBody fixture, 7fc3ef1):
// every member as it marshals them, a registration with its secret part.
const anspBody = `{"schema":"occurrence/v1","report_ref":"ANSP-OCC-2026-0001","channel":"mandatory",` +
	`"occurred_at":"2026-10-03T10:00:00.000Z","became_aware_at":"2026-10-03T10:05:00.000Z","category":"airprox",` +
	`"reporter":{"org":"ansp-01","person_ref":"staff-0042"},` +
	`"aircraft":[{"serial":"TEST1581F5FHD2344","operator_reg":"FIN87astrdge12k8-xyz"}],` +
	`"manned":[{"icao24":"4ca7b5","callsign":"TST123"}],"intent_refs":["2f8343be-6482-4d1b-a474-16847e01af1e"],` +
	`"min_separation":{"h_m":180,"v_m":40,"at":"2026-10-03T10:00:00.000Z"},` +
	`"narrative":"Synthetic airprox between a UAS and a manned aircraft.","evidence_urls":[],` +
	`"reported_at":"2026-10-03T10:06:00.000Z"}`

var (
	officer   = audit.Actor{Type: audit.ActorUser, ID: "officer-1", Realm: audit.RealmConsole}
	anspActor = audit.Actor{Type: audit.ActorClient, ID: "ansp-01"}
	usspActor = audit.Actor{Type: audit.ActorClient, ID: "ussp-tst-01"}
)

func decode(t testing.TB, body string) *gen.OccurrenceReport {
	t.Helper()
	var b gen.OccurrenceReport
	if err := json.Unmarshal([]byte(body), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}

func mutate(t testing.TB, body string, f func(m map[string]any)) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func input(t testing.TB, body string) Input {
	t.Helper()
	in, err := Normalise(decode(t, body), PublicPartOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func newSealer(t testing.TB, id string) *pii.Sealer {
	t.Helper()
	key := make([]byte, pii.KeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := pii.NewSealer(id, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// memStore is the Store in memory, with the database's rules restated:
// received_at is its clock, within_72h is Within, (reporter_org,
// report_ref) is unique, and a failed transaction leaves nothing.
type memStore struct {
	mu      sync.Mutex
	now     time.Time
	reports map[string]Report
	exports []Export
	events  []audit.Event
}

func newMem(now time.Time) *memStore { return &memStore{now: now, reports: map[string]Report{}} }

type memTx struct {
	m       *memStore
	reports map[string]Report
	exports []Export
	events  []audit.Event
}

func (m *memStore) WithTx(_ context.Context, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := &memTx{m: m, reports: maps.Clone(m.reports), exports: slices.Clone(m.exports), events: slices.Clone(m.events)}
	if err := fn(tx); err != nil {
		return err
	}
	m.reports, m.exports, m.events = tx.reports, tx.exports, tx.events
	return nil
}

func (m *memStore) Get(_ context.Context, id string) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.reports[id]
	if !ok {
		return Report{}, ErrNotFound
	}
	return r, nil
}

func (m *memStore) List(_ context.Context, f Filter) ([]Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Report
	for id := range m.reports {
		r := m.reports[id]
		if (f.State == "" || r.State == f.State) && (f.Category == "" || r.Category == f.Category) && (f.Channel == "" || r.Channel == f.Channel) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	if len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (m *memStore) eventsOf(eventType string) []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for i := range m.events {
		if m.events[i].EventType == eventType {
			out = append(out, m.events[i])
		}
	}
	return out
}

func (t *memTx) Now(context.Context) (time.Time, error) { return t.m.now, nil }

func (t *memTx) Insert(_ context.Context, r *NewReport) (Report, bool, error) {
	for id := range t.reports {
		if held := t.reports[id]; held.ReporterOrg == r.ReporterOrg && held.ReportRef == r.ReportRef {
			return Report{}, false, nil
		}
	}
	rep := Report{ID: r.ID, ReporterOrg: r.ReporterOrg, ReportRef: r.ReportRef, Channel: r.Channel, Origin: r.Origin,
		PersonSealed: r.PersonSealed, PersonKeyID: r.PersonKeyID, OccurredAt: r.OccurredAt, BecameAwareAt: r.BecameAwareAt,
		ReportedAt: r.ReportedAt, ReceivedAt: t.m.now, DeadlineS: r.DeadlineS,
		Within72h: Within(r.BecameAwareAt, t.m.now, time.Duration(r.DeadlineS)*time.Second), Category: r.Category,
		Aircraft: r.Aircraft, Manned: r.Manned, IntentRefs: r.IntentRefs, MinSeparation: r.MinSeparation, Narrative: r.Narrative,
		EvidenceURLs: r.EvidenceURLs, ContentHash: r.ContentHash, State: StateReceived, UpdatedAt: t.m.now}
	t.reports[r.ID] = rep
	return rep, true, nil
}

func (t *memTx) ByKey(_ context.Context, org, ref string) (Report, error) {
	for id := range t.reports {
		if r := t.reports[id]; r.ReporterOrg == org && r.ReportRef == ref {
			return r, nil
		}
	}
	return Report{}, ErrNotFound
}

func (t *memTx) Get(_ context.Context, id string) (Report, error) {
	r, ok := t.reports[id]
	if !ok {
		return Report{}, ErrNotFound
	}
	return r, nil
}

func (t *memTx) GetForUpdate(ctx context.Context, id string) (Report, error) { return t.Get(ctx, id) }

func (t *memTx) Classify(_ context.Context, id, class, actor string) (Report, error) {
	r := t.reports[id]
	now := t.m.now
	r.RiskClassification, r.ClassifiedAt, r.ClassifiedBy, r.UpdatedBy = class, &now, actor, actor
	if r.State == StateReceived {
		r.State = StateClassified
	}
	t.reports[id] = r
	return r, nil
}

func (t *memTx) UpdateAnalysis(_ context.Context, id, analysis, followUp, state, actor string) (Report, error) {
	r := t.reports[id]
	r.Analysis, r.FollowUp, r.State, r.UpdatedBy = analysis, followUp, state, actor
	r.ClosedAt = nil
	if state == StateClosed {
		now := t.m.now
		r.ClosedAt = &now
	}
	t.reports[id] = r
	return r, nil
}

func (t *memTx) Received(_ context.Context, from, to time.Time, limit int) ([]Report, error) {
	var out []Report
	for id := range t.reports {
		if r := t.reports[id]; !r.ReceivedAt.Before(from) && r.ReceivedAt.Before(to) {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) InsertExport(_ context.Context, e *Export) error {
	t.exports = append(t.exports, *e)
	return nil
}

func (t *memTx) Audit(_ context.Context, ev audit.Event) error {
	if err := audit.DefaultCatalogue().Validate(ev); err != nil {
		return err
	}
	t.events = append(t.events, ev)
	return nil
}

var errBoom = errors.New("boom")

// service is a Service on a memory store at now.
func service(t testing.TB, now time.Time, sealer *pii.Sealer) (*Service, *memStore) {
	t.Helper()
	m := newMem(now)
	seq := 0
	s := &Service{Store: m, Sealer: sealer, PublicPart: PublicPartOf(nil), Deadline: 72 * time.Hour, ClockSkew: 5 * time.Minute,
		RiskClasses: []string{"serious_incident", "incident", "occurrence_without_safety_effect"}, Exporters: DefaultExporters(),
		DefaultFormat: FormatECCAIRSDraft, MaxExportRecords: 10, Counters: &core.Counters{},
		NewID: func(time.Time) string {
			seq++
			return ulidOf(seq)
		}}
	return s, m
}

// ulidOf is a valid ULID numbered n (n < 1000).
func ulidOf(n int) string {
	const digits = "0123456789"
	return "01KAAAAAAAAAAAAAAAAAAAA" + string([]byte{digits[n/100%10], digits[n/10%10], digits[n%10]})
}
