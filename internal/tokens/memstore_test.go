package tokens

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// memStore is an in-memory Store with transactions that roll back: a
// failing fn leaves clients, keys and events as they were. Events are
// validated by the real audit catalogue.
type memStore struct {
	mu      sync.Mutex
	clients map[string]ClientRecord
	keys    []KeyRow
	events  []audit.Event
	// failRecord makes Record fail (an audit outage).
	failRecord bool
	// failReads makes the non-transactional reads fail.
	failReads bool
}

func newMemStore() *memStore { return &memStore{clients: map[string]ClientRecord{}} }

var errStoreDown = errors.New("store down")

func (m *memStore) InTx(_ context.Context, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	clients := maps.Clone(m.clients)
	keys := slices.Clone(m.keys)
	events := slices.Clone(m.events)
	if err := fn(memTx{m}); err != nil {
		m.clients, m.keys, m.events = clients, keys, events
		return err
	}
	return nil
}

func (m *memStore) ClientRecord(_ context.Context, id string) (ClientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return ClientRecord{}, errStoreDown
	}
	c, ok := m.clients[id]
	if !ok {
		return ClientRecord{}, ErrNotFound
	}
	return c, nil
}

func (m *memStore) Clients(context.Context) ([]ClientRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return nil, errStoreDown
	}
	out := make([]ClientRecord, 0, len(m.clients))
	for _, id := range slices.Sorted(maps.Keys(m.clients)) {
		out = append(out, m.clients[id])
	}
	slices.SortFunc(out, func(a, b ClientRecord) int {
		if a.ID < b.ID {
			return -1
		}
		return 1
	})
	return out, nil
}

func (m *memStore) SigningKeys(context.Context) ([]KeyRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return nil, errStoreDown
	}
	return slices.Clone(m.keys), nil
}

func (m *memStore) eventsOf(eventType string) []audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for ri := range m.events {
		e := &m.events[ri]
		if e.EventType == eventType {
			out = append(out, *e)
		}
	}
	return out
}

// memTx runs inside InTx, which holds m.mu.
type memTx struct{ m *memStore }

func (t memTx) Lock(context.Context, string) error { return nil }

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

func (t memTx) ClientRecord(_ context.Context, id string) (ClientRecord, error) {
	c, ok := t.m.clients[id]
	if !ok {
		return ClientRecord{}, ErrNotFound
	}
	return c, nil
}

func (t memTx) InsertClient(_ context.Context, c ClientRecord) (ClientRecord, error) {
	if _, dup := t.m.clients[c.ID]; dup {
		return ClientRecord{}, errors.New("duplicate key")
	}
	t.m.clients[c.ID] = c
	return c, nil
}

func (t memTx) UpdateClient(_ context.Context, c ClientRecord) (ClientRecord, error) {
	old, ok := t.m.clients[c.ID]
	if !ok {
		return ClientRecord{}, ErrNotFound
	}
	old.Scopes, old.Audiences, old.Status, old.Note, old.UpdatedAt, old.UpdatedBy = c.Scopes, c.Audiences, c.Status, c.Note, c.UpdatedAt, c.UpdatedBy
	t.m.clients[c.ID] = old
	return old, nil
}

func (t memTx) SigningKeys(context.Context) ([]KeyRow, error) { return slices.Clone(t.m.keys), nil }

func (t memTx) InsertSigningKey(_ context.Context, r KeyRow) error {
	if slices.ContainsFunc(t.m.keys, func(k KeyRow) bool { return k.KID == r.KID }) {
		return nil
	}
	t.m.keys = append(t.m.keys, r)
	return nil
}

func (t memTx) row(kid string) *KeyRow {
	for i := range t.m.keys {
		if t.m.keys[i].KID == kid {
			return &t.m.keys[i]
		}
	}
	return nil
}

func (t memTx) SetSigningKeyRef(_ context.Context, kid, ref string) error {
	if r := t.row(kid); r != nil {
		r.PrivateRef = ref
	}
	return nil
}

func (t memTx) ActivateSigningKey(_ context.Context, kid string, at time.Time) error {
	if r := t.row(kid); r != nil && r.ActiveFrom == nil {
		r.ActiveFrom, r.RequestedBy, r.RequestedAt = &at, "", nil
	}
	return nil
}

func (t memTx) RetireSigningKey(_ context.Context, kid string, at time.Time) error {
	if r := t.row(kid); r != nil && r.ActiveFrom != nil && r.RetiredAt == nil {
		r.RetiredAt = &at
	}
	return nil
}

func (t memTx) RequestKeyRotation(_ context.Context, kid, by string, at time.Time) error {
	if r := t.row(kid); r != nil && r.ActiveFrom == nil {
		r.RequestedBy, r.RequestedAt = by, &at
	}
	return nil
}
