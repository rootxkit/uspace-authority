package ltest

import (
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// ViolationStore is api's ALRT consumer running for the scenario, and
// what it wrote to the relational database.
type ViolationStore struct {
	s        *Stack
	Durable  string
	Counters *core.Counters
}

// StoredViolation is a violations row as api stored it.
type StoredViolation struct {
	ID, Kind, Track, State, Severity string
	ZoneID                           *string
	ClearReason                      *string
	Peak                             *float64
	TerrainDataset                   *string
	InUSpace                         bool
	Opened, Created                  time.Time
	Closed                           *time.Time
	// Events are the event types of its events rows, in order.
	Events []string
}

// Rows reads every violation with its events rows.
func (v *ViolationStore) Rows() []StoredViolation {
	t := v.s.T
	t.Helper()
	q, err := v.s.PGAdmin.Query(`SELECT violation_id, kind, track_id, detector_state, severity, zone_id, clear_reason, peak_value,
		terrain_source->>'dataset', in_uspace, opened_at, created_at, closed_at FROM violations ORDER BY created_at, violation_id`)
	if err != nil {
		t.Fatalf("ltest: read violations: %v", err)
	}
	defer func() { _ = q.Close() }()
	var out []StoredViolation
	for q.Next() {
		var r StoredViolation
		if err := q.Scan(&r.ID, &r.Kind, &r.Track, &r.State, &r.Severity, &r.ZoneID, &r.ClearReason, &r.Peak, &r.TerrainDataset,
			&r.InUSpace, &r.Opened, &r.Created, &r.Closed); err != nil {
			t.Fatalf("ltest: read violations: %v", err)
		}
		out = append(out, r)
	}
	if err := q.Err(); err != nil {
		t.Fatalf("ltest: read violations: %v", err)
	}
	for i := range out {
		out[i].Events = v.events("violation", out[i].ID)
	}
	return out
}

// events are the event types of an entity's events rows, in order.
func (v *ViolationStore) events(entityType, id string) []string {
	return v.s.EventTypes(entityType, id)
}

// EventTypes are the event types of an entity's events rows, in order.
func (s *Stack) EventTypes(entityType, id string) []string {
	s.T.Helper()
	q, err := s.PGAdmin.Query(`SELECT event_type FROM events WHERE entity_type = $1 AND entity_id = $2 ORDER BY id`, entityType, id)
	if err != nil {
		s.T.Fatalf("ltest: read events: %v", err)
	}
	defer func() { _ = q.Close() }()
	var out []string
	for q.Next() {
		var e string
		if err := q.Scan(&e); err != nil {
			s.T.Fatalf("ltest: read events: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// Find is the stored violation with id, or nil.
func (v *ViolationStore) Find(id string) *StoredViolation {
	rows := v.Rows()
	for i := range rows {
		if rows[i].ID == id {
			return &rows[i]
		}
	}
	return nil
}

// Store is the running violation store, or nil before
// StartViolationStore.
func (s *Stack) Store() *ViolationStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store
}
