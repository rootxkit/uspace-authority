package zonesvc

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// memStore is Store in memory with real transactions: a failed InTx
// leaves the state as it was, so tests see rollbacks.
type memStore struct {
	mu      sync.Mutex
	now     time.Time
	state   memState
	failTx  error // when set, InTx fails at commit with it
	lockLog []string
}

type memState struct {
	versions     []Version
	publications []Publication
	payloads     map[int64][]byte
	events       []audit.Event
	seq          int64
	nextID       int64
}

func (s memState) clone() memState {
	c := s
	c.versions = make([]Version, len(s.versions))
	for i := range s.versions {
		v := s.versions[i]
		v.Feature = append(json.RawMessage{}, v.Feature...)
		c.versions[i] = v
	}
	c.publications = slices.Clone(s.publications)
	c.events = slices.Clone(s.events)
	c.payloads = make(map[int64][]byte, len(s.payloads))
	for k, v := range s.payloads {
		c.payloads[k] = v
	}
	return c
}

func newMemStore(now time.Time) *memStore {
	return &memStore{now: now, state: memState{payloads: map[int64][]byte{}}}
}

var _ Store = (*memStore)(nil)

func (m *memStore) InTx(_ context.Context, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	work := m.state.clone()
	tx := &memTx{m: m, s: &work}
	if err := fn(tx); err != nil {
		return err
	}
	if m.failTx != nil {
		return m.failTx
	}
	m.state = work
	return nil
}

func (m *memStore) Now(context.Context) (time.Time, error) { return m.now, nil }

func latestOf(vs []Version, identifier string) (Version, bool) {
	var best Version
	found := false
	for i := range vs {
		if vs[i].Identifier == identifier && (!found || vs[i].ZoneVersion > best.ZoneVersion) {
			best, found = vs[i], true
		}
	}
	return best, found
}

func (m *memStore) Latest(_ context.Context, identifier string) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := latestOf(m.state.versions, identifier)
	if !ok {
		return Version{}, ErrNotFound
	}
	return v, nil
}

func (m *memStore) Version(_ context.Context, identifier string, zoneVersion int) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.state.versions {
		if v := &m.state.versions[i]; v.Identifier == identifier && v.ZoneVersion == zoneVersion {
			return *v, nil
		}
	}
	return Version{}, ErrNotFound
}

func (m *memStore) Versions(_ context.Context, identifier string, before, limit int) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Version
	for i := range m.state.versions {
		if v := &m.state.versions[i]; v.Identifier == identifier && v.ZoneVersion < before {
			out = append(out, *v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ZoneVersion > out[j].ZoneVersion })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *memStore) List(_ context.Context, f ListFilter) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := map[string]bool{}
	for i := range m.state.versions {
		if v := &m.state.versions[i]; v.Dataset == f.Dataset && v.Identifier > f.After {
			ids[v.Identifier] = true
		}
	}
	var out []Version
	for id := range ids {
		v, _ := latestOf(m.state.versions, id)
		if f.State == "" || v.State == f.State {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	if len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func inForceOf(vs []Version, ds Dataset, at time.Time) []Version {
	best := map[string]Version{}
	for i := range vs {
		v := &vs[i]
		if v.Dataset != ds || v.PublishedVersion == nil || at.Before(v.ValidFrom) || at.After(v.ValidTo) {
			continue
		}
		if b, ok := best[v.Identifier]; !ok || v.ZoneVersion > b.ZoneVersion {
			best[v.Identifier] = *v
		}
	}
	out := make([]Version, 0, len(best))
	for id := range best {
		out = append(out, best[id])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identifier < out[j].Identifier })
	return out
}

func (m *memStore) InForce(_ context.Context, ds Dataset, at time.Time) ([]Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return inForceOf(m.state.versions, ds, at), nil
}

// events and publications for assertions.
func (m *memStore) events() []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.state.events)
}

func (m *memStore) publications() []Publication {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.state.publications)
}

func (m *memStore) payload(id int64) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state.payloads[id]
}

type memTx struct {
	m *memStore
	s *memState
}

func (t *memTx) Lock(_ context.Context, name string) error {
	t.m.lockLog = append(t.m.lockLog, name)
	return nil
}

func (t *memTx) TryLock(_ context.Context, name string) (bool, error) {
	t.m.lockLog = append(t.m.lockLog, "try:"+name)
	return true, nil
}

func (t *memTx) Record(_ context.Context, ev audit.Event) error {
	if err := audit.DefaultCatalogue().Validate(ev); err != nil {
		return err
	}
	t.s.events = append(t.s.events, ev)
	return nil
}

func (t *memTx) Now(context.Context) (time.Time, error) { return t.m.now, nil }

func (t *memTx) NextZonesVersion(context.Context) (int64, error) {
	t.s.seq++
	return t.s.seq, nil
}

func (t *memTx) LatestForUpdate(_ context.Context, identifier string) (Version, error) {
	v, ok := latestOf(t.s.versions, identifier)
	if !ok {
		return Version{}, ErrNotFound
	}
	return v, nil
}

func (t *memTx) Insert(_ context.Context, d *Draft, zoneVersion int, by string) (Version, error) {
	for i := range t.s.versions {
		if v := &t.s.versions[i]; v.Identifier == d.Identifier && v.ZoneVersion == zoneVersion {
			return Version{}, ErrDuplicate
		}
	}
	t.s.nextID++
	v := Version{
		ID: t.s.nextID, Dataset: d.Dataset, Identifier: d.Identifier, ZoneVersion: zoneVersion, State: StateDraft,
		Type: d.Columns.Type, Country: d.Columns.Country, Feature: append(json.RawMessage{}, d.Feature...),
		ValidFrom: d.ValidFrom, ValidTo: d.ValidTo, WGS84Fields: d.Columns.WGS84Fields, CreatedAt: t.m.now,
		CreatedBy: by, Designation: d.Designation,
	}
	t.s.versions = append(t.s.versions, v)
	return v, nil
}

func (t *memTx) SupersedeUnpublished(_ context.Context, identifier string) error {
	for i := range t.s.versions {
		v := &t.s.versions[i]
		if v.Identifier == identifier && (v.State == StateDraft || v.State == StateApproved) {
			v.State = StateSuperseded
		}
	}
	return nil
}

func (t *memTx) Approve(_ context.Context, identifier string, zoneVersion int, by string) (Version, error) {
	for i := range t.s.versions {
		v := &t.s.versions[i]
		if v.Identifier == identifier && v.ZoneVersion == zoneVersion && v.State == StateDraft {
			now := t.m.now
			v.State, v.ApprovedAt, v.ApprovedBy = StateApproved, &now, by
			return *v, nil
		}
	}
	return Version{}, ErrNotFound
}

func (t *memTx) PublishApproved(_ context.Context, ds Dataset, version int64, by string) ([]Version, error) {
	var out []Version
	for i := range t.s.versions {
		v := &t.s.versions[i]
		if v.Dataset == ds && v.State == StateApproved {
			now, pv := t.m.now, version
			v.State, v.PublishedVersion, v.PublishedAt, v.PublishedBy = StatePublished, &pv, &now, by
			out = append(out, *v)
		}
	}
	return out, nil
}

func (t *memTx) SupersedeOlderPublished(_ context.Context, identifier string, zoneVersion int) error {
	for i := range t.s.versions {
		v := &t.s.versions[i]
		if v.Identifier == identifier && v.State == StatePublished && v.ZoneVersion < zoneVersion {
			v.State = StateSuperseded
		}
	}
	return nil
}

func (t *memTx) InForce(_ context.Context, ds Dataset, at time.Time) ([]Version, error) {
	return inForceOf(t.s.versions, ds, at), nil
}

func (t *memTx) Projectable(_ context.Context, at time.Time) ([]Version, error) {
	var out []Version
	for i := range t.s.versions {
		if v := &t.s.versions[i]; v.PublishedVersion != nil && !v.ValidTo.Before(at) {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (t *memTx) MaxPublishedVersion(context.Context) (int64, error) {
	var n int64
	for i := range t.s.versions {
		if v := &t.s.versions[i]; v.PublishedVersion != nil {
			n = max(n, *v.PublishedVersion)
		}
	}
	return n, nil
}

func (t *memTx) EnqueuePublication(_ context.Context, p PublicationInput) (Publication, error) {
	for i := range t.s.publications {
		if t.s.publications[i].Dataset == p.Dataset && t.s.publications[i].State == "pending" {
			t.s.publications[i].State = "superseded"
		}
	}
	out := Publication{
		ID: int64(len(t.s.publications) + 1), Dataset: p.Dataset, Version: p.Version, PayloadHash: p.PayloadHash,
		FeatureCount: p.FeatureCount, State: "pending", CreatedAt: t.m.now,
	}
	t.s.publications = append(t.s.publications, out)
	t.s.payloads[out.ID] = p.Payload
	return out, nil
}

// memProjection is Projection in memory, failing on demand.
type memProjection struct {
	mu      sync.Mutex
	rows    map[string]ProjectedZone
	version int64
	fail    error
	writes  int
}

func newMemProjection() *memProjection { return &memProjection{rows: map[string]ProjectedZone{}} }

func (p *memProjection) Replace(_ context.Context, rows []ProjectedZone, _ time.Time, zonesVersion int64) (int64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != nil {
		return 0, p.fail
	}
	p.writes++
	keep := map[string]ProjectedZone{}
	for i := range rows {
		keep[rows[i].key()] = rows[i]
	}
	var deleted int64
	for k := range p.rows {
		if _, ok := keep[k]; !ok {
			deleted++
		}
	}
	p.rows, p.version = keep, zonesVersion
	return deleted, nil
}

func (p *memProjection) keys() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.rows))
	for k := range p.rows {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// rowsAsLoaded is the projection as a reader would load it.
func (p *memProjection) rowsAsLoaded() []ProjectedRow {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]ProjectedRow, 0, len(p.rows))
	for k := range p.rows {
		r := p.rows[k]
		out = append(out, ProjectedRow{
			Dataset: r.Dataset, Identifier: r.Identifier, ZoneVersion: r.ZoneVersion, Feature: r.Feature,
			ValidFrom: r.ValidFrom, ValidTo: r.ValidTo, ZonesVersion: p.version,
		})
	}
	return out
}

// memPublisher records announcements.
type memPublisher struct {
	mu       sync.Mutex
	versions []int64
	fail     error
}

func (p *memPublisher) PublishZonesVersion(_ context.Context, v int64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != nil {
		return p.fail
	}
	p.versions = append(p.versions, v)
	return nil
}

var errInjected = errors.New("injected failure")
