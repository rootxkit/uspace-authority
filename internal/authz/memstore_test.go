package authz

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

// memStore is an in-memory Store whose transactions roll back on error.
type memStore struct {
	mu         sync.Mutex
	users      map[string]User
	passwords  map[string]string
	mfa        map[string]MFA
	challenges map[string]Challenge
	sessions   map[string]Session
	events     []audit.Event
	failRecord bool
	failReads  bool
}

func newMemStore() *memStore {
	return &memStore{users: map[string]User{}, passwords: map[string]string{}, mfa: map[string]MFA{},
		challenges: map[string]Challenge{}, sessions: map[string]Session{}}
}

var errDown = errors.New("store down")

func (m *memStore) InTx(_ context.Context, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, p, f, c, s, e := maps.Clone(m.users), maps.Clone(m.passwords), maps.Clone(m.mfa), maps.Clone(m.challenges), maps.Clone(m.sessions), slices.Clone(m.events)
	if err := fn(memTx{m}); err != nil {
		m.users, m.passwords, m.mfa, m.challenges, m.sessions, m.events = u, p, f, c, s, e
		return err
	}
	return nil
}

func (m *memStore) UserByID(_ context.Context, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return User{}, errDown
	}
	return memTx{m}.UserByID(context.Background(), id)
}

func (m *memStore) UserByUsername(_ context.Context, name string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return User{}, errDown
	}
	return memTx{m}.UserByUsername(context.Background(), name)
}

func (m *memStore) Users(_ context.Context, limit int32) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return nil, errDown
	}
	var out []User
	for _, id := range slices.Sorted(maps.Keys(m.users)) {
		out = append(out, m.users[id])
	}
	slices.SortFunc(out, func(a, b User) int {
		if a.Username < b.Username {
			return -1
		}
		return 1
	})
	if len(out) > int(limit) {
		out = out[:limit]
	}
	return out, nil
}

func (m *memStore) PasswordHash(_ context.Context, id string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return "", errDown
	}
	h, ok := m.passwords[id]
	if !ok {
		return "", ErrNotFound
	}
	return h, nil
}

func (m *memStore) MFA(_ context.Context, id string) (MFA, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return MFA{}, errDown
	}
	return memTx{m}.MFA(context.Background(), id)
}

func (m *memStore) Session(_ context.Context, jti string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failReads {
		return Session{}, errDown
	}
	s, ok := m.sessions[jti]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (m *memStore) TouchSession(_ context.Context, jti string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.sessions[jti]; ok && s.RevokedAt == nil && s.LastSeenAt.Before(at) {
		s.LastSeenAt = at
		m.sessions[jti] = s
	}
	return nil
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

func (t memTx) UserByID(_ context.Context, id string) (User, error) {
	u, ok := t.m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (t memTx) UserByUsername(_ context.Context, name string) (User, error) {
	for id := range t.m.users {
		if t.m.users[id].Username == name {
			return t.m.users[id], nil
		}
	}
	return User{}, ErrNotFound
}

func (t memTx) CountUsers(context.Context) (int64, error) { return int64(len(t.m.users)), nil }

func (t memTx) CountActiveAdmins(context.Context) (int64, error) {
	var n int64
	for id := range t.m.users {
		u := t.m.users[id]
		if u.Status == StatusActive && u.Realm == "console" && slices.Contains(u.Roles, "admin") {
			n++
		}
	}
	return n, nil
}

func (t memTx) InsertUser(_ context.Context, u User) (User, error) {
	u.Status, u.UpdatedAt, u.UpdatedBy = StatusActive, u.CreatedAt, u.CreatedBy
	t.m.users[u.ID] = u
	return u, nil
}

func (t memTx) SetUserRoles(_ context.Context, id string, roles []string, at time.Time, by string) (User, error) {
	u, ok := t.m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Roles, u.UpdatedAt, u.UpdatedBy = slices.Clone(roles), at, by
	t.m.users[id] = u
	return u, nil
}

func (t memTx) SetUserStatus(_ context.Context, id, status string, at time.Time, by string) (User, error) {
	u, ok := t.m.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	u.Status, u.UpdatedAt, u.UpdatedBy = status, at, by
	t.m.users[id] = u
	return u, nil
}

func (t memTx) SetPassword(_ context.Context, id, hash string, _ time.Time) error {
	t.m.passwords[id] = hash
	return nil
}

func (t memTx) MFA(_ context.Context, id string) (MFA, error) {
	f, ok := t.m.mfa[id]
	if !ok {
		return MFA{}, ErrNotFound
	}
	f.RecoveryHashes = slices.Clone(f.RecoveryHashes)
	return f, nil
}

func (t memTx) SaveMFA(_ context.Context, f MFA, _ time.Time) error {
	t.m.mfa[f.UserID] = f
	return nil
}

func (t memTx) DeleteMFA(_ context.Context, id string) error {
	delete(t.m.mfa, id)
	return nil
}

func (t memTx) InsertChallenge(_ context.Context, c Challenge) error {
	t.m.challenges[c.TokenHash] = c
	return nil
}

func (t memTx) ChallengeForUpdate(_ context.Context, h string) (Challenge, error) {
	c, ok := t.m.challenges[h]
	if !ok {
		return Challenge{}, ErrNotFound
	}
	return c, nil
}

func (t memTx) CountChallengeAttempt(_ context.Context, h string) error {
	c := t.m.challenges[h]
	c.Attempts++
	t.m.challenges[h] = c
	return nil
}

func (t memTx) UseChallenge(_ context.Context, h string, at time.Time) error {
	c := t.m.challenges[h]
	c.UsedAt = &at
	t.m.challenges[h] = c
	return nil
}

func (t memTx) InsertSession(_ context.Context, s Session) error {
	t.m.sessions[s.JTI] = s
	return nil
}

func (t memTx) LiveSessions(_ context.Context, id string, now time.Time) ([]Session, error) {
	var out []Session
	for _, jti := range slices.Sorted(maps.Keys(t.m.sessions)) {
		s := t.m.sessions[jti]
		if s.UserID == id && s.RevokedAt == nil && s.ExpiresAt.After(now) {
			out = append(out, s)
		}
	}
	slices.SortStableFunc(out, func(a, b Session) int { return a.IssuedAt.Compare(b.IssuedAt) })
	return out, nil
}

func (t memTx) RevokeSession(_ context.Context, jti string, at time.Time, _, reason string) (bool, error) {
	s, ok := t.m.sessions[jti]
	if !ok || s.RevokedAt != nil {
		return false, nil
	}
	s.RevokedAt, s.RevokeReason = &at, reason
	t.m.sessions[jti] = s
	return true, nil
}

func (t memTx) RevokeUserSessions(ctx context.Context, id string, at time.Time, by, reason string) ([]string, error) {
	var out []string
	for _, jti := range slices.Sorted(maps.Keys(t.m.sessions)) {
		s := t.m.sessions[jti]
		if s.UserID == id && s.RevokedAt == nil && s.ExpiresAt.After(at) {
			_, _ = t.RevokeSession(ctx, jti, at, by, reason)
			out = append(out, jti)
		}
	}
	return out, nil
}

func (t memTx) DeleteExpiredSessions(_ context.Context, before time.Time) (int64, error) {
	var n int64
	for jti := range t.m.sessions {
		if t.m.sessions[jti].ExpiresAt.Before(before) {
			delete(t.m.sessions, jti)
			n++
		}
	}
	return n, nil
}

func (t memTx) DeleteExpiredChallenges(_ context.Context, before time.Time) (int64, error) {
	var n int64
	for h, c := range t.m.challenges {
		if c.ExpiresAt.Before(before) {
			delete(t.m.challenges, h)
			n++
		}
	}
	return n, nil
}
