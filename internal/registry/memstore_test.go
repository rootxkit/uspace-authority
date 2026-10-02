package registry

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
)

// memStore is an in-memory Store whose transactions roll back: a failing
// fn leaves every table and the events as they were. Events are
// validated by the real audit catalogue. It enforces the unique keys and
// the operator reference the migration enforces.
type memStore struct {
	mu        sync.Mutex
	operators map[string]OperatorRecord
	uas       map[string]UAS
	pilots    map[string]PilotRecord
	changes   []Change
	events    []audit.Event
	version   int64
	locks     []string
	// failRecord makes Record fail (an audit outage); failReads the
	// reads outside a transaction; failFacts the re-projection's read.
	failRecord bool
	failReads  bool
	failFacts  bool
	// lockHeld makes TryLock report another holder.
	lockHeld bool
	// failCommit makes the commit fail after fn succeeded.
	failCommit bool
}

func newMemStore() *memStore {
	return &memStore{operators: map[string]OperatorRecord{}, uas: map[string]UAS{}, pilots: map[string]PilotRecord{}}
}

var errStoreDown = errors.New("store down")

func clonePilots(m map[string]PilotRecord) map[string]PilotRecord {
	out := make(map[string]PilotRecord, len(m))
	for k := range m {
		v := m[k]
		v.Competencies = slices.Clone(v.Competencies)
		out[k] = v
	}
	return out
}

func (m *memStore) InTx(_ context.Context, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ops, uas, pilots := maps.Clone(m.operators), maps.Clone(m.uas), clonePilots(m.pilots)
	changes, events := slices.Clone(m.changes), slices.Clone(m.events)
	err := fn(memTx{m})
	if err == nil && m.failCommit {
		err = errors.New("commit: connection lost")
	}
	if err != nil {
		m.operators, m.uas, m.pilots, m.changes, m.events = ops, uas, pilots, changes, events
		return err
	}
	return nil
}

func (m *memStore) read() error {
	if m.failReads {
		return errStoreDown
	}
	return nil
}

func (m *memStore) Operator(_ context.Context, id string) (OperatorRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return OperatorRecord{}, err
	}
	r, ok := m.operators[id]
	if !ok {
		return OperatorRecord{}, ErrNotFound
	}
	return r, nil
}

func (m *memStore) OperatorByKey(_ context.Context, key string) (OperatorRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return OperatorRecord{}, err
	}
	return memTx{m}.byKey(key)
}

func sortedValues[V any](m map[string]V, id func(V) string) []V {
	out := slices.Collect(maps.Values(m))
	slices.SortFunc(out, func(a, b V) int { return cmp.Compare(id(a), id(b)) })
	return out
}

func page[V any](rows []V, id func(V) string, p Page) []V {
	var out []V
	for _, r := range rows {
		if id(r) > p.After && len(out) < int(limitOf(p)) {
			out = append(out, r)
		}
	}
	return out
}

func (m *memStore) Operators(_ context.Context, f OperatorFilter) ([]OperatorRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return nil, err
	}
	id := func(r OperatorRecord) string { return r.ID }
	var rows []OperatorRecord
	all := sortedValues(m.operators, id)
	for i := range all {
		if r := &all[i]; (f.Key == "" || r.Key == f.Key) && (f.Status == "" || r.Status == f.Status) {
			rows = append(rows, *r)
		}
	}
	return page(rows, id, f.Page), nil
}

func (m *memStore) UAS(_ context.Context, id string) (UAS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return UAS{}, err
	}
	u, ok := m.uas[id]
	if !ok {
		return UAS{}, ErrNotFound
	}
	return u, nil
}

func (m *memStore) UASByFold(_ context.Context, fold string) ([]UAS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return nil, err
	}
	return memTx{m}.UASByFold(context.Background(), fold)
}

func (m *memStore) UASList(_ context.Context, f UASFilter) ([]UAS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return nil, err
	}
	id := func(u UAS) string { return u.ID }
	var rows []UAS
	all := sortedValues(m.uas, id)
	for i := range all {
		u := &all[i]
		if (f.SerialFold == "" || u.SerialFold == f.SerialFold) && (f.OperatorID == "" || u.OperatorID == f.OperatorID) &&
			(f.Status == "" || u.Status == f.Status) {
			rows = append(rows, *u)
		}
	}
	return page(rows, id, f.Page), nil
}

func (m *memStore) Pilot(_ context.Context, id string) (PilotRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return PilotRecord{}, err
	}
	p, ok := m.pilots[id]
	if !ok {
		return PilotRecord{}, ErrNotFound
	}
	return p, nil
}

func (m *memStore) Pilots(_ context.Context, f PilotFilter) ([]PilotRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return nil, err
	}
	id := func(p PilotRecord) string { return p.ID }
	var rows []PilotRecord
	all := sortedValues(m.pilots, id)
	for i := range all {
		if p := &all[i]; (f.OperatorID == "" || p.OperatorID == f.OperatorID) && (f.Status == "" || p.Status == f.Status) {
			rows = append(rows, *p)
		}
	}
	return page(rows, id, f.Page), nil
}

func (m *memStore) Changes(_ context.Context, since int64, limit int) ([]Change, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.read(); err != nil {
		return nil, err
	}
	var out []Change
	for _, c := range m.changes {
		if c.Seq > since && len(out) < limit {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *memStore) eventTypes() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.events))
	for i := range m.events {
		out = append(out, m.events[i].EventType)
	}
	return out
}

type memTx struct{ m *memStore }

func (t memTx) Lock(_ context.Context, name string) error {
	t.m.locks = append(t.m.locks, name)
	return nil
}

func (t memTx) TryLock(_ context.Context, name string) (bool, error) {
	if t.m.lockHeld {
		return false, nil
	}
	t.m.locks = append(t.m.locks, name)
	return true, nil
}

func (t memTx) Record(_ context.Context, ev audit.Event) error {
	if t.m.failRecord {
		return errors.New("audit down")
	}
	if err := audit.DefaultCatalogue().Validate(ev); err != nil {
		return err
	}
	t.m.events = append(t.m.events, ev)
	return nil
}

func (t memTx) NextVersion(context.Context) (int64, error) {
	t.m.version++
	return t.m.version, nil
}

func (t memTx) byKey(key string) (OperatorRecord, error) {
	for id := range t.m.operators {
		if r := t.m.operators[id]; r.Key == key {
			return r, nil
		}
	}
	return OperatorRecord{}, ErrNotFound
}

func (t memTx) InsertOperator(_ context.Context, r OperatorRecord) (OperatorRecord, error) {
	if _, err := t.byKey(r.Key); err == nil {
		return OperatorRecord{}, ErrDuplicate
	}
	r.HasSecretPart = r.SecretHash != ""
	if r.Authorisations == nil {
		r.Authorisations = []byte("[]")
	}
	t.m.operators[r.ID] = r
	return r, nil
}

func (t memTx) OperatorForUpdate(_ context.Context, id string) (OperatorRecord, error) {
	r, ok := t.m.operators[id]
	if !ok {
		return OperatorRecord{}, ErrNotFound
	}
	return r, nil
}

func (t memTx) OperatorByKey(_ context.Context, key string) (OperatorRecord, error) {
	return t.byKey(key)
}

func (t memTx) UpdateOperator(_ context.Context, r OperatorRecord) (OperatorRecord, error) {
	if _, ok := t.m.operators[r.ID]; !ok {
		return OperatorRecord{}, ErrNotFound
	}
	t.m.operators[r.ID] = r
	return r, nil
}

func (t memTx) SetOperatorStatus(_ context.Context, u StatusUpdate) (OperatorRecord, error) {
	r, ok := t.m.operators[u.ID]
	if !ok {
		return OperatorRecord{}, ErrNotFound
	}
	r.Status, r.StatusReason, r.RegistryVersion, r.UpdatedAt, r.UpdatedBy = u.Status, u.Reason, u.Version, u.At, u.By
	t.m.operators[u.ID] = r
	return r, nil
}

func (t memTx) ExpiredOperatorIDs(_ context.Context, now time.Time, limit int) ([]string, error) {
	var out []string
	all := sortedValues(t.m.operators, func(r OperatorRecord) string { return r.ID })
	for i := range all {
		if r := &all[i]; (r.Status == StatusActive || r.Status == StatusSuspended) && !r.ValidUntil.After(now) && len(out) < limit {
			out = append(out, r.ID)
		}
	}
	return out, nil
}

func (t memTx) InsertUAS(_ context.Context, u UAS) (UAS, error) {
	if _, ok := t.m.operators[u.OperatorID]; !ok {
		return UAS{}, errors.New("foreign key violation")
	}
	for id := range t.m.uas {
		if e := t.m.uas[id]; e.SerialFold == u.SerialFold || e.ManufacturerCode == u.ManufacturerCode && e.Serial == u.Serial {
			return UAS{}, ErrDuplicate
		}
	}
	t.m.uas[u.ID] = u
	return u, nil
}

func (t memTx) UASForUpdate(_ context.Context, id string) (UAS, error) {
	u, ok := t.m.uas[id]
	if !ok {
		return UAS{}, ErrNotFound
	}
	return u, nil
}

func (t memTx) UASByFold(_ context.Context, fold string) ([]UAS, error) {
	out := []UAS{}
	all := sortedValues(t.m.uas, func(u UAS) string { return u.ID })
	for i := range all {
		if all[i].SerialFold == fold {
			out = append(out, all[i])
		}
	}
	return out, nil
}

func (t memTx) UpdateUAS(_ context.Context, u UAS) (UAS, error) {
	if _, ok := t.m.uas[u.ID]; !ok {
		return UAS{}, ErrNotFound
	}
	t.m.uas[u.ID] = u
	return u, nil
}

func (t memTx) SetUASStatus(_ context.Context, s StatusUpdate) (UAS, error) {
	u, ok := t.m.uas[s.ID]
	if !ok {
		return UAS{}, ErrNotFound
	}
	u.Status, u.StatusReason, u.RegistryVersion, u.UpdatedAt, u.UpdatedBy = s.Status, s.Reason, s.Version, s.At, s.By
	t.m.uas[s.ID] = u
	return u, nil
}

func (t memTx) InsertPilot(_ context.Context, r PilotRecord) (PilotRecord, error) {
	for id := range t.m.pilots {
		if t.m.pilots[id].PersonRefHash == r.PersonRefHash {
			return PilotRecord{}, ErrDuplicate
		}
	}
	if r.Competencies == nil {
		r.Competencies = []Competency{}
	}
	t.m.pilots[r.ID] = r
	return r, nil
}

func (t memTx) PilotForUpdate(_ context.Context, id string) (PilotRecord, error) {
	p, ok := t.m.pilots[id]
	if !ok {
		return PilotRecord{}, ErrNotFound
	}
	return p, nil
}

func (t memTx) PilotByPersonRef(_ context.Context, hash string) (PilotRecord, error) {
	for id := range t.m.pilots {
		if p := t.m.pilots[id]; p.PersonRefHash == hash {
			return p, nil
		}
	}
	return PilotRecord{}, ErrNotFound
}

func (t memTx) UpdatePilot(_ context.Context, r PilotRecord) (PilotRecord, error) {
	if _, ok := t.m.pilots[r.ID]; !ok {
		return PilotRecord{}, ErrNotFound
	}
	t.m.pilots[r.ID] = r
	return r, nil
}

func (t memTx) SetPilotStatus(_ context.Context, s StatusUpdate) (PilotRecord, error) {
	p, ok := t.m.pilots[s.ID]
	if !ok {
		return PilotRecord{}, ErrNotFound
	}
	p.Status, p.StatusReason, p.RegistryVersion, p.UpdatedAt, p.UpdatedBy = s.Status, s.Reason, s.Version, s.At, s.By
	t.m.pilots[s.ID] = p
	return p, nil
}

func (t memTx) UpsertCompetency(_ context.Context, pilotID string, c Competency) error {
	p, ok := t.m.pilots[pilotID]
	if !ok {
		return ErrNotFound
	}
	p.Competencies = slices.DeleteFunc(slices.Clone(p.Competencies), func(x Competency) bool { return x.Competency == c.Competency })
	p.Competencies = append(p.Competencies, c)
	slices.SortFunc(p.Competencies, func(a, b Competency) int { return cmp.Compare(a.Competency, b.Competency) })
	t.m.pilots[pilotID] = p
	return nil
}

func (t memTx) InsertChange(_ context.Context, c Change) (int64, error) {
	c.Seq = int64(len(t.m.changes)) + 1
	t.m.changes = append(t.m.changes, c)
	return c.Seq, nil
}

func (t memTx) Facts(context.Context) (Facts, error) {
	if t.m.failFacts {
		return Facts{}, errStoreDown
	}
	var f Facts
	ops := sortedValues(t.m.operators, func(r OperatorRecord) string { return r.ID })
	for i := range ops {
		f.Operators = append(f.Operators, projectOperator(&ops[i].Operator))
	}
	uas := sortedValues(t.m.uas, func(u UAS) string { return u.ID })
	for i := range uas {
		f.UAS = append(f.UAS, projectUAS(&uas[i]))
	}
	return f, nil
}

// memProjection is a Projection in memory with the projection tables'
// semantics: a change's upsert never replaces a newer row, a repair's
// replaces any, nothing is deleted.
type memProjection struct {
	mu        sync.Mutex
	operators map[string]ProjectedOperator
	uas       map[string]ProjectedUAS
	inReg     map[string]bool
	// failBegin, failUAS and failCommit inject the failures of SC-17
	// step 3 at each point of the write.
	failBegin  bool
	failUAS    bool
	failCommit bool
	writes     int
}

func newMemProjection() *memProjection {
	return &memProjection{operators: map[string]ProjectedOperator{}, uas: map[string]ProjectedUAS{}, inReg: map[string]bool{}}
}

var errProjectionDown = errors.New("telemetry database down")

func (p *memProjection) Begin(context.Context) (ProjectionTx, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failBegin {
		return nil, errProjectionDown
	}
	return &memProjectionTx{p: p, ops: maps.Clone(p.operators), uas: maps.Clone(p.uas), inReg: maps.Clone(p.inReg)}, nil
}

type memProjectionTx struct {
	p     *memProjection
	ops   map[string]ProjectedOperator
	uas   map[string]ProjectedUAS
	inReg map[string]bool
}

func (t *memProjectionTx) UpsertOperators(_ context.Context, rows []ProjectedOperator, _ time.Time, repair bool) error {
	for _, r := range rows {
		if old, ok := t.ops[r.OperatorID]; repair || !ok || old.Version <= r.Version {
			t.ops[r.OperatorID] = r
		}
	}
	return nil
}

func (t *memProjectionTx) UpsertUAS(_ context.Context, rows []ProjectedUAS, _ time.Time, repair bool) error {
	if t.p.failUAS && len(rows) > 0 {
		return errProjectionDown
	}
	for _, r := range rows {
		if old, ok := t.uas[r.UASID]; repair || !ok || old.Version <= r.Version {
			t.uas[r.UASID] = r
			t.inReg[r.UASID] = true
		}
	}
	return nil
}

func (t *memProjectionTx) MarkMissing(_ context.Context, operatorIDs, uasIDs []string, _ time.Time) (int64, error) {
	var n int64
	for id, o := range t.ops {
		if !slices.Contains(operatorIDs, id) && o.Status != StatusUnregistered {
			o.Status = StatusUnregistered
			t.ops[id] = o
			n++
		}
	}
	for id := range t.uas {
		if !slices.Contains(uasIDs, id) && t.inReg[id] {
			t.inReg[id] = false
			n++
		}
	}
	return n, nil
}

func (t *memProjectionTx) Commit(context.Context) error {
	t.p.mu.Lock()
	defer t.p.mu.Unlock()
	if t.p.failCommit {
		return errProjectionDown
	}
	t.p.operators, t.p.uas, t.p.inReg = t.ops, t.uas, t.inReg
	t.p.writes++
	return nil
}

func (t *memProjectionTx) Rollback(context.Context) {}

// LoadProjection makes memProjection a ProjectionSource too: its rows
// go through toLoaded, the mapping TSSource uses, so a reader is driven
// from what the service wrote.
func (p *memProjection) LoadProjection(context.Context) (Loaded, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failBegin {
		return Loaded{}, errProjectionDown
	}
	ops := []reader.ProjRegistryOperator{}
	for _, o := range sortedValues(p.operators, func(o ProjectedOperator) string { return o.OperatorID }) {
		ops = append(ops, reader.ProjRegistryOperator{
			OperatorID: o.OperatorID, RegistrationNumberPublic: o.RegistrationNumber, Status: o.Status, RegistryVersion: o.Version,
		})
	}
	uas := []reader.ProjRegistryUAS{}
	for _, u := range sortedValues(p.uas, func(u ProjectedUAS) string { return u.UASID }) {
		var op *string
		if u.OperatorID != "" {
			id := u.OperatorID
			op = &id
		}
		uas = append(uas, reader.ProjRegistryUAS{
			UasID: u.UASID, Label: u.Label, Serial: u.Serial, SerialFold: u.SerialFold, RegistrationStatus: u.Status,
			OperatorID: op, InRegistry: p.inReg[u.UASID], RegistryVersion: u.Version,
		})
	}
	return toLoaded(ops, uas), nil
}
