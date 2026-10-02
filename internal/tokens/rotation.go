package tokens

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the key manager.
const (
	CounterKeyRefreshFailed  = "signing_key_refresh_failed"   // a re-read of signing_keys failed; the last state signs on
	CounterKeyFileMissing    = "signing_key_file_missing"     // the active kid's file is not configured on this replica
	CounterKeyRotated        = "signing_key_rotated"          // a rotation activated the next key
	CounterKeyRotationRefuse = "signing_key_rotation_refused" // a rotation was refused (no candidate, same admin)
	CounterKeyCompromised    = "signing_key_compromised"      // a key dropped in an emergency
)

// keyLock serialises key registration and rotation across replicas.
const keyLock = "signing_keys"

// KeyManager keeps signing_keys and the in-memory Keys in step: it
// registers the configured files, activates the first one on an empty
// table, follows rotations made by other replicas, and rotates.
type KeyManager struct {
	Store    Store
	Keys     *Keys
	Counters *core.Counters
	Logger   *slog.Logger
	// TwoPerson requires a second admin to confirm a rotation within
	// ConfirmWindow (T4).
	TwoPerson     bool
	ConfirmWindow time.Duration
	Now           func() time.Time
	// OnChange is called after a new state was applied (the verifier of
	// this issuer's own tokens rebuilds its key set).
	OnChange func()
}

func (m *KeyManager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *KeyManager) count(name string) {
	if m.Counters != nil {
		m.Counters.Inc(name)
	}
}

func (m *KeyManager) logger() *slog.Logger {
	if m.Logger == nil {
		return logging.Discard()
	}
	return m.Logger
}

var keyActor = audit.SystemActor("token-service")

// Sync registers every configured key that signing_keys does not hold
// (an event each), records a moved file, activates the first configured
// token key when none is active (bootstrap), activates a newly
// configured publication key in place of the previous one, and applies
// the result. At start a failure stops the process.
func (m *KeyManager) Sync(ctx context.Context) error {
	now := m.now()
	err := m.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, keyLock); err != nil {
			return err
		}
		rows, err := tx.SigningKeys(ctx)
		if err != nil {
			return err
		}
		have := map[string]KeyRow{}
		for ri := range rows {
			r := &rows[ri]
			have[r.KID] = *r
		}
		register := func(f KeyFile, purpose string) error {
			r, ok := have[f.KID]
			if ok {
				if r.Purpose != purpose {
					return fmt.Errorf("key %s is registered for %s and configured for %s; a key serves one purpose", f.KID, r.Purpose, purpose)
				}
				if r.PrivateRef != f.Ref {
					return tx.SetSigningKeyRef(ctx, f.KID, f.Ref)
				}
				return nil
			}
			row := KeyRow{KID: f.KID, Purpose: purpose, PublicJWK: f.PublicJWK, PrivateRef: f.Ref, RegisteredAt: now}
			if err := tx.InsertSigningKey(ctx, row); err != nil {
				return err
			}
			have[f.KID] = row
			return tx.Record(ctx, audit.Event{
				Actor: keyActor, EntityType: "signing_key", EntityID: f.KID, EventType: audit.EventSigningKeyRegistered,
				Payload: map[string]any{"kid": f.KID, "purpose": purpose, "private_ref": f.Ref},
			})
		}
		for _, f := range m.Keys.Files() {
			if err := register(f, PurposeToken); err != nil {
				return err
			}
		}
		if p := m.Keys.Publication(); p != nil {
			if err := register(*p, PurposePublication); err != nil {
				return err
			}
		}
		rows, err = tx.SigningKeys(ctx)
		if err != nil {
			return err
		}
		if err := m.bootstrapToken(ctx, tx, rows, now); err != nil {
			return err
		}
		return m.switchPublication(ctx, tx, rows, now)
	})
	if err != nil {
		return fmt.Errorf("signing keys: %w", err)
	}
	return m.Refresh(ctx)
}

func (m *KeyManager) bootstrapToken(ctx context.Context, tx Tx, rows []KeyRow, now time.Time) error {
	for ri := range rows {
		r := &rows[ri]
		if r.Purpose == PurposeToken && r.Active() {
			return nil
		}
	}
	first := m.Keys.Files()[0].KID
	if err := tx.ActivateSigningKey(ctx, first, now); err != nil {
		return err
	}
	return tx.Record(ctx, audit.Event{
		Actor: keyActor, EntityType: "signing_key", EntityID: first, EventType: audit.EventSigningKeyActivated,
		Payload: map[string]any{"kid": first, "purpose": PurposeToken, "reason": "bootstrap: no token key was active"},
	})
}

func (m *KeyManager) switchPublication(ctx context.Context, tx Tx, rows []KeyRow, now time.Time) error {
	p := m.Keys.Publication()
	if p == nil {
		return nil
	}
	var previous string
	for ri := range rows {
		r := &rows[ri]
		if r.Purpose != PurposePublication || !r.Active() {
			continue
		}
		if r.KID == p.KID {
			return nil
		}
		previous = r.KID
		if err := tx.RetireSigningKey(ctx, r.KID, now); err != nil {
			return err
		}
	}
	if err := tx.ActivateSigningKey(ctx, p.KID, now); err != nil {
		return err
	}
	return tx.Record(ctx, audit.Event{
		Actor: keyActor, EntityType: "signing_key", EntityID: p.KID, EventType: audit.EventSigningKeyActivated,
		Payload: map[string]any{"kid": p.KID, "purpose": PurposePublication, "previous_kid": previous, "reason": "configured"},
	})
}

// Refresh re-reads signing_keys and applies it. When the active key's
// file is not configured here the previous state keeps signing and the
// error is returned (counted).
func (m *KeyManager) Refresh(ctx context.Context) error {
	rows, err := m.Store.SigningKeys(ctx)
	if err != nil {
		m.count(CounterKeyRefreshFailed)
		return fmt.Errorf("read signing keys: %w", err)
	}
	err = m.Keys.Apply(rows)
	if errors.Is(err, ErrNoActiveKey) {
		m.count(CounterKeyFileMissing)
	}
	// The published rows changed even when no key may sign: the
	// verifier of this issuer's own tokens follows them either way.
	if m.OnChange != nil {
		m.OnChange()
	}
	return err
}

// Run refreshes every interval until ctx ends, so every replica follows
// a rotation made by another one and drops retired keys from the JWKS.
func (m *KeyManager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Refresh(ctx); err != nil && ctx.Err() == nil {
				logging.Error(ctx, m.logger(), "signing key refresh failed; the last state signs on", err,
					slog.String("active_kid", m.Keys.ActiveKID()))
			}
		}
	}
}

// Rotation is the outcome of Rotate.
type Rotation struct {
	// State is "requested" (the first admin's half of the two-person
	// rule) or "activated".
	State         string
	KID           string
	ActiveKID     string
	PreviousKID   string
	RequestedBy   string
	ConfirmBefore time.Time
}

// Rotation refusal reasons.
const (
	ReasonNoCandidate = "no_candidate"
	ReasonSameAdmin   = "same_admin"
)

// Rotate activates the next configured token key (NextCandidate). With
// the two-person rule the first call records the request and a second
// admin's call within ConfirmWindow activates; the same admin twice, or
// no candidate, is refused with 409 and a key_rotation_refused event.
func (m *KeyManager) Rotate(ctx context.Context, actor audit.Actor) (Rotation, error) {
	now := m.now()
	var out Rotation
	var refusal error
	err := m.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, keyLock); err != nil {
			return err
		}
		rows, err := tx.SigningKeys(ctx)
		if err != nil {
			return err
		}
		var current string
		for ri := range rows {
			r := &rows[ri]
			if r.Purpose == PurposeToken && r.Active() {
				current = r.KID
			}
		}
		order := make([]string, 0, len(m.Keys.Files()))
		for _, f := range m.Keys.Files() {
			order = append(order, f.KID)
		}
		next, ok := NextCandidate(order, rows)
		if !ok {
			refusal = httpx.Refuse(http.StatusConflict, httpx.SlugConflict,
				"no key to rotate to: add a PEM file to SIGNING_KEY_FILES on every replica and restart",
				core.Fieldf("SIGNING_KEY_FILES", "every configured key has been active already"))
			return m.refused(ctx, tx, actor, "", ReasonNoCandidate)
		}
		pending := next.RequestedAt != nil && now.Before(next.RequestedAt.Add(m.ConfirmWindow))
		if m.TwoPerson && !pending {
			if err := tx.RequestKeyRotation(ctx, next.KID, actor.ID, now); err != nil {
				return err
			}
			out = Rotation{State: "requested", KID: next.KID, ActiveKID: current, RequestedBy: actor.ID, ConfirmBefore: now.Add(m.ConfirmWindow)}
			return tx.Record(ctx, audit.Event{
				Actor: actor, EntityType: "signing_key", EntityID: next.KID, EventType: audit.EventKeyRotationRequested,
				Payload: map[string]any{"kid": next.KID, "active_kid": current, "confirm_before": out.ConfirmBefore},
			})
		}
		if m.TwoPerson && next.RequestedBy == actor.ID {
			refusal = httpx.Refuse(http.StatusConflict, httpx.SlugConflict,
				"the two-person rule needs a second admin to confirm this rotation",
				core.Fieldf("actor", "%s requested this rotation and cannot confirm it", actor.ID))
			return m.refused(ctx, tx, actor, next.KID, ReasonSameAdmin)
		}
		if current != "" {
			if err := tx.RetireSigningKey(ctx, current, now); err != nil {
				return err
			}
		}
		if err := tx.ActivateSigningKey(ctx, next.KID, now); err != nil {
			return err
		}
		out = Rotation{State: "activated", KID: next.KID, ActiveKID: next.KID, PreviousKID: current, RequestedBy: next.RequestedBy}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "signing_key", EntityID: next.KID, EventType: audit.EventSigningKeyActivated,
			Payload: map[string]any{
				"kid": next.KID, "purpose": PurposeToken, "previous_kid": current, "reason": "rotation",
				"requested_by": next.RequestedBy, "confirmed_by": actor.ID, "two_person": m.TwoPerson,
			},
		})
	})
	if err != nil {
		return Rotation{}, fmt.Errorf("rotate signing key: %w", err)
	}
	if refusal != nil {
		m.count(CounterKeyRotationRefuse)
		return Rotation{}, refusal
	}
	if out.State == "activated" {
		m.count(CounterKeyRotated)
		if err := m.Refresh(ctx); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Compromise is the emergency retirement of the key kid (token or
// publication): it leaves the JWKS at once, never signs again and is
// never a rotation candidate. An active token key is replaced by the
// next candidate in the same transaction; without one, this issuer
// stops issuing tokens and sessions until a key is added. One admin
// suffices (an emergency must not wait for a second), and the act is a
// signing_key_compromised event naming the reason. Other replicas
// follow within KEY_REFRESH_S; verifiers that cached the JWKS keep the
// key until their cache expires, which is why this is not the routine
// rotation.
func (m *KeyManager) Compromise(ctx context.Context, kid, reason string, actor audit.Actor) (KeyRow, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 1000 {
		return KeyRow{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "", core.Fieldf("reason", "required, at most 1000 bytes"))
	}
	now := m.now()
	var out KeyRow
	err := m.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, keyLock); err != nil {
			return err
		}
		rows, err := tx.SigningKeys(ctx)
		if err != nil {
			return err
		}
		i := slices.IndexFunc(rows, func(r KeyRow) bool { return r.KID == kid })
		if i < 0 {
			return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such key", core.Fieldf("kid", "%s is not registered", quote(kid)))
		}
		row := rows[i]
		if row.CompromisedAt != nil {
			return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "the key is marked compromised already", core.Fieldf("kid", "%s", quote(kid)))
		}
		if err := tx.CompromiseSigningKey(ctx, kid, now, actor.ID, reason); err != nil {
			return err
		}
		replacement := ""
		if row.Purpose == PurposeToken && row.Active() {
			order := make([]string, 0, len(m.Keys.Files()))
			for _, f := range m.Keys.Files() {
				order = append(order, f.KID)
			}
			if next, ok := NextCandidate(order, rows); ok {
				if err := tx.ActivateSigningKey(ctx, next.KID, now); err != nil {
					return err
				}
				replacement = next.KID
				if err := tx.Record(ctx, audit.Event{
					Actor: actor, EntityType: "signing_key", EntityID: next.KID, EventType: audit.EventSigningKeyActivated,
					Payload: map[string]any{"kid": next.KID, "purpose": PurposeToken, "previous_kid": kid, "reason": "compromise"},
				}); err != nil {
					return err
				}
			}
		}
		if err := tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "signing_key", EntityID: kid, EventType: audit.EventSigningKeyCompromised,
			Payload: map[string]any{"kid": kid, "purpose": row.Purpose, "reason": reason, "was_active": row.Active(), "replacement_kid": replacement},
		}); err != nil {
			return err
		}
		after, err := tx.SigningKeys(ctx)
		if err != nil {
			return err
		}
		out = after[slices.IndexFunc(after, func(r KeyRow) bool { return r.KID == kid })]
		return nil
	})
	if err != nil {
		return KeyRow{}, err
	}
	m.count(CounterKeyCompromised)
	if err := m.Refresh(ctx); err != nil && !errors.Is(err, ErrNoActiveKey) {
		return out, err
	}
	return out, nil
}

func (m *KeyManager) refused(ctx context.Context, tx Tx, actor audit.Actor, kid, reason string) error {
	entity := kid
	if entity == "" {
		entity = "none"
	}
	return tx.Record(ctx, audit.Event{
		Actor: actor, EntityType: "signing_key", EntityID: entity, EventType: audit.EventKeyRotationRefused,
		Payload: map[string]any{"kid": kid, "reason": reason},
	})
}
