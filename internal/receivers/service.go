package receivers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Event types of the receiver registry (internal/audit catalogue).
const (
	EventCreated           = audit.EventRIDReceiverCreated
	EventUpdated           = audit.EventRIDReceiverUpdated
	EventStatusChanged     = audit.EventRIDReceiverStatusChanged
	EventKeysRotated       = audit.EventRIDReceiverKeysRotated
	EventDeleted           = audit.EventRIDReceiverDeleted
	EventPositionDeviation = audit.EventRIDReceiverPositionDeviation
	entityType             = "rid_receiver"
)

// Problem slugs of the registry.
const (
	SlugKeyStoreUnavailable = "key_store_unavailable"
	SlugNotFound            = httpx.SlugNotFound
	SlugConflict            = httpx.SlugConflict
)

// Counter names of the registry (E-09).
const (
	CounterKeyStoreRefused    = "key_store_write_refused"
	CounterReprojected        = "keyset_reprojected"
	CounterReprojectFailed    = "keyset_reproject_failed"
	CounterStaleKeysDeleted   = "keyset_stale_entries_deleted"
	CounterPositionDeviations = "position_deviations"
	CounterHeartbeats         = "heartbeats"
)

// ErrNotFound is an unknown receiver id.
var ErrNotFound = httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such receiver")

// KeyStore is where the key set is projected for rid-ingest (KV bucket
// rid_receiver_keys). A write that fails refuses the change it belongs
// to (LESSONS B-09).
type KeyStore interface {
	Put(ctx context.Context, e Entry) error
	Delete(ctx context.Context, id string) error
	Keys(ctx context.Context) ([]string, error)
}

// Service is the receiver registry of api.
type Service struct {
	DB            *pg.DB
	Audit         *audit.Writer
	Sealer        *pii.Sealer
	Hasher        *passhash.Hasher
	Keys          KeyStore
	Defaults      Defaults
	RotationGrace time.Duration
	Now           func() time.Time
	Counters      *core.Counters
	Logger        *slog.Logger
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return logging.Discard()
}

func aad(id string, generation int) []byte {
	return []byte("rid_receivers|" + id + "|" + strconv.Itoa(generation) + "|hmac_secret")
}

func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case store.IsNoRows(err):
		return ErrNotFound
	case store.SQLState(err) == store.StateUniqueViolation:
		return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "a receiver with this id exists")
	}
	return err
}

// keyStoreRefused is the refusal of a change the key set could not take.
func (s *Service) keyStoreRefused(err error) error {
	s.Counters.Inc(CounterKeyStoreRefused)
	logging.Error(context.Background(), s.logger(), "receiver key set write failed; change refused", err)
	return httpx.Refuse(http.StatusServiceUnavailable, SlugKeyStoreUnavailable,
		"the receiver key set cannot be written now; nothing was changed, retry later")
}

// entryOf opens the row's secrets and builds its key-set entry.
func (s *Service) entryOf(r *row) (Entry, error) {
	cur, err := s.Sealer.Open(r.PiiKeyID, r.HmacSecretEnc, aad(r.ID, int(r.KeyGeneration)))
	if err != nil {
		return Entry{}, fmt.Errorf("receiver %s: current secret: %w", r.ID, err)
	}
	e := Entry{
		ReceiverID: r.ID, Status: r.Status, DisabledBy: r.DisabledBy, DisabledReason: r.DisabledReason,
		LatDeg: r.LatDeg, LonDeg: r.LonDeg, Version: r.Version,
		Keys: []KeyGeneration{{Generation: int(r.KeyGeneration), BearerHash: r.KeyHash, HMACSecretHex: hex.EncodeToString(cur)}},
	}
	if r.PrevKeyHash != nil && r.PrevPiiKeyID != nil && r.PrevValidUntil != nil {
		prev, err := s.Sealer.Open(*r.PrevPiiKeyID, r.PrevHmacSecretEnc, aad(r.ID, int(r.KeyGeneration)-1))
		if err != nil {
			return Entry{}, fmt.Errorf("receiver %s: previous secret: %w", r.ID, err)
		}
		until := *r.PrevValidUntil
		e.Keys = append(e.Keys, KeyGeneration{Generation: int(r.KeyGeneration) - 1, BearerHash: *r.PrevKeyHash,
			HMACSecretHex: hex.EncodeToString(prev), NotAfter: &until})
	}
	return e, nil
}

// put projects r inside the transaction; a failure refuses the change.
func (s *Service) put(ctx context.Context, r *row) error {
	e, err := s.entryOf(r)
	if err != nil {
		return err
	}
	if err := s.Keys.Put(ctx, e); err != nil {
		return s.keyStoreRefused(err)
	}
	return nil
}

func (s *Service) record(ctx context.Context, q *gen.Queries, actor audit.Actor, eventType, id string, payload any) error {
	_, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: entityType, EntityID: id, EventType: eventType, Payload: payload})
	return err
}

// Create registers a receiver with new keys, shown once.
func (s *Service) Create(ctx context.Context, actor audit.Actor, n NewReceiver) (Receiver, Credentials, error) {
	if err := n.Validate(); err != nil {
		return Receiver{}, Credentials{}, err
	}
	creds, secret, err := GenerateCredentials(n.ID, 1)
	if err != nil {
		return Receiver{}, Credentials{}, err
	}
	hash, err := s.Hasher.Hash(creds.BearerKey)
	if err != nil {
		return Receiver{}, Credentials{}, err
	}
	sealed, err := s.Sealer.Seal(secret, aad(n.ID, 1))
	if err != nil {
		return Receiver{}, Credentials{}, err
	}
	cfg, err := json.Marshal(n.Config)
	if err != nil {
		return Receiver{}, Credentials{}, err
	}
	now := s.now()
	var out Receiver
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		ins, err := q.InsertReceiver(ctx, gen.InsertReceiverParams{
			ID: n.ID, Name: n.Name, LatDeg: n.LatDeg, LonDeg: n.LonDeg, Owner: n.Owner, OwnerName: n.OwnerName,
			KeyHash: hash, PiiKeyID: s.Sealer.KeyID(), HmacSecretEnc: sealed, Config: cfg,
			CreatedAt: now, CreatedBy: actor.ID,
		})
		if err != nil {
			return mapErr(err)
		}
		r := row(ins)
		if out, err = receiverFrom(&r); err != nil {
			return err
		}
		if err := s.record(ctx, q, actor, EventCreated, n.ID, map[string]any{
			"name": n.Name, "lat_deg": n.LatDeg, "lon_deg": n.LonDeg, "owner": n.Owner, "key_generation": 1,
		}); err != nil {
			return err
		}
		return s.put(ctx, &r)
	})
	if err != nil {
		return Receiver{}, Credentials{}, err
	}
	return out, creds, nil
}

// Get returns one receiver.
func (s *Service) Get(ctx context.Context, id string) (Receiver, error) {
	r, err := s.DB.Queries().ReceiverByID(ctx, id)
	if err != nil {
		return Receiver{}, mapErr(err)
	}
	return receiverFrom(&r)
}

// List returns one page in id order and the after of the next page.
func (s *Service) List(ctx context.Context, after string, limit int) ([]Receiver, string, error) {
	rows, err := s.DB.Queries().ListReceivers(ctx, gen.ListReceiversParams{AfterID: after, PageSize: int32(limit)})
	if err != nil {
		return nil, "", err
	}
	out := make([]Receiver, 0, len(rows))
	for i := range rows {
		r := row(rows[i])
		rec, err := receiverFrom(&r)
		if err != nil {
			return nil, "", err
		}
		out = append(out, rec)
	}
	next := ""
	if len(rows) == limit && limit > 0 {
		next = rows[len(rows)-1].ID
	}
	return out, next, nil
}

// change runs fn on the locked row, writes the row and the event and
// projects the result, all in one transaction.
func (s *Service) change(ctx context.Context, actor audit.Actor, id, eventType string, fn func(r *row) (any, error)) (Receiver, error) {
	var out Receiver
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		locked, err := q.ReceiverForUpdate(ctx, id)
		if err != nil {
			return mapErr(err)
		}
		r := row(locked)
		payload, err := fn(&r)
		if err != nil {
			return err
		}
		r.UpdatedAt, r.UpdatedBy = s.now(), actor.ID
		if err := q.UpdateReceiver(ctx, gen.UpdateReceiverParams{
			ID: r.ID, Name: r.Name, LatDeg: r.LatDeg, LonDeg: r.LonDeg, Owner: r.Owner, OwnerName: r.OwnerName,
			KeyGeneration: r.KeyGeneration, KeyHash: r.KeyHash, PiiKeyID: r.PiiKeyID, HmacSecretEnc: r.HmacSecretEnc,
			PrevKeyHash: r.PrevKeyHash, PrevPiiKeyID: r.PrevPiiKeyID, PrevHmacSecretEnc: r.PrevHmacSecretEnc,
			PrevValidUntil: r.PrevValidUntil, Status: r.Status, DisabledBy: r.DisabledBy, DisabledReason: r.DisabledReason,
			DisabledAt: r.DisabledAt, Config: r.Config, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
		}); err != nil {
			return mapErr(err)
		}
		r.Version++
		if err := s.record(ctx, q, actor, eventType, id, payload); err != nil {
			return err
		}
		if out, err = receiverFrom(&r); err != nil {
			return err
		}
		return s.put(ctx, &r)
	})
	return out, err
}

// Update changes a receiver's name, pinned position, owner or config.
func (s *Service) Update(ctx context.Context, actor audit.Actor, id string, p Patch) (Receiver, error) {
	return s.change(ctx, actor, id, EventUpdated, func(r *row) (any, error) {
		changed := map[string]any{}
		var errs []error
		if p.Name != nil {
			if !validName(*p.Name) {
				errs = append(errs, core.Fieldf("label", "1 to 200 characters"))
			}
			r.Name = *p.Name
			changed["name"] = *p.Name
		}
		if (p.LatDeg == nil) != (p.LonDeg == nil) {
			errs = append(errs, core.Fieldf("lat_deg", "lat_deg and lon_deg change together"))
		} else if p.LatDeg != nil {
			if !validPosition(*p.LatDeg, *p.LonDeg) {
				errs = append(errs, core.Fieldf("lat_deg", "the pinned position is not a valid WGS84 position"))
			}
			r.LatDeg, r.LonDeg = *p.LatDeg, *p.LonDeg
			changed["lat_deg"], changed["lon_deg"] = *p.LatDeg, *p.LonDeg
		}
		if p.Owner != nil {
			if !validOwner(*p.Owner) {
				errs = append(errs, core.Fieldf("owner", "must be authority or third_party"))
			}
			r.Owner = *p.Owner
			changed["owner"] = *p.Owner
		}
		if p.OwnerName != nil {
			if len(*p.OwnerName) > 200 {
				errs = append(errs, core.Fieldf("owner_name", "at most 200 characters"))
			}
			r.OwnerName = p.OwnerName
			changed["owner_name"] = *p.OwnerName
		}
		if p.Config != nil {
			if err := p.Config.Validate(); err != nil {
				errs = append(errs, err)
			}
			cfg, err := json.Marshal(p.Config)
			if err != nil {
				return nil, err
			}
			r.Config = cfg
			changed["config"] = p.Config
		}
		if len(changed) == 0 && len(errs) == 0 {
			errs = append(errs, core.Fieldf("body", "nothing to change"))
		}
		return changed, errors.Join(errs...)
	})
}

// SetStatus disables or enables a receiver, recording who and why.
func (s *Service) SetStatus(ctx context.Context, actor audit.Actor, id, status, reason string) (Receiver, error) {
	if status != StatusEnabled && status != StatusDisabled {
		return Receiver{}, core.Fieldf("status", "must be enabled or disabled")
	}
	if reason == "" || len(reason) > 500 {
		return Receiver{}, core.Fieldf("reason", "1 to 500 characters")
	}
	return s.change(ctx, actor, id, EventStatusChanged, func(r *row) (any, error) {
		from := r.Status
		r.Status = status
		if status == StatusDisabled {
			now := s.now()
			who := actor.ID
			r.DisabledBy, r.DisabledReason, r.DisabledAt = &who, &reason, &now
		} else {
			r.DisabledBy, r.DisabledReason, r.DisabledAt = nil, nil, nil
		}
		return map[string]any{"from": from, "to": status, "reason": reason}, nil
	})
}

// Rotate issues a new key generation, shown once; the previous one keeps
// working for grace (nil: the configured default; 0: revoked now).
func (s *Service) Rotate(ctx context.Context, actor audit.Actor, id string, grace *time.Duration) (Receiver, Credentials, error) {
	g := s.RotationGrace
	if grace != nil {
		g = *grace
	}
	if g < 0 || g > 7*24*time.Hour {
		return Receiver{}, Credentials{}, core.Fieldf("grace_s", "must be 0 to 604800")
	}
	var creds Credentials
	out, err := s.change(ctx, actor, id, EventKeysRotated, func(r *row) (any, error) {
		next := int(r.KeyGeneration) + 1
		c, secret, err := GenerateCredentials(r.ID, next)
		if err != nil {
			return nil, err
		}
		hash, err := s.Hasher.Hash(c.BearerKey)
		if err != nil {
			return nil, err
		}
		sealed, err := s.Sealer.Seal(secret, aad(r.ID, next))
		if err != nil {
			return nil, err
		}
		payload := map[string]any{"from_generation": r.KeyGeneration, "to_generation": next, "grace_s": int64(g / time.Second)}
		if g > 0 {
			until := s.now().Add(g)
			hashPrev, keyPrev := r.KeyHash, r.PiiKeyID
			r.PrevKeyHash, r.PrevPiiKeyID, r.PrevHmacSecretEnc, r.PrevValidUntil = &hashPrev, &keyPrev, r.HmacSecretEnc, &until
			payload["previous_valid_until"] = until
		} else {
			r.PrevKeyHash, r.PrevPiiKeyID, r.PrevHmacSecretEnc, r.PrevValidUntil = nil, nil, nil, nil
		}
		r.KeyGeneration, r.KeyHash, r.PiiKeyID, r.HmacSecretEnc = int32(next), hash, s.Sealer.KeyID(), sealed
		creds = c
		return payload, nil
	})
	if err != nil {
		return Receiver{}, Credentials{}, err
	}
	return out, creds, nil
}

// Delete removes a receiver and its key-set entry; its observations stay.
func (s *Service) Delete(ctx context.Context, actor audit.Actor, id, reason string) error {
	if reason == "" || len(reason) > 500 {
		return core.Fieldf("reason", "1 to 500 characters")
	}
	return s.DB.WithTx(ctx, func(q *gen.Queries) error {
		r, err := q.ReceiverForUpdate(ctx, id)
		if err != nil {
			return mapErr(err)
		}
		if _, err := q.DeleteReceiver(ctx, id); err != nil {
			return err
		}
		if err := s.record(ctx, q, actor, EventDeleted, id, map[string]any{
			"reason": reason, "name": r.Name, "key_generation": r.KeyGeneration,
		}); err != nil {
			return err
		}
		if err := s.Keys.Delete(ctx, id); err != nil {
			return s.keyStoreRefused(err)
		}
		return nil
	})
}

// EntryFor reads one receiver's key-set entry from the registry (api's
// own authentication of the config and heartbeat endpoints).
func (s *Service) EntryFor(ctx context.Context, id string) (Entry, error) {
	r, err := s.DB.Queries().ReceiverByID(ctx, id)
	if err != nil {
		return Entry{}, mapErr(err)
	}
	return s.entryOf(&r)
}

// HeartbeatIn is a verified heartbeat.
type HeartbeatIn struct {
	Position *Position
	Firmware *string
}

// HeartbeatResult is what the heartbeat recorded.
type HeartbeatResult struct {
	Receiver           Receiver
	SeenAt             time.Time
	DeviationM         *float64
	PositionToleranceM float64
}

// Heartbeat records a verified heartbeat: last seen on api's clock, the
// reported position and its distance from the pinned one (uspace-core
// geodesy, Vincenty), counted when beyond the tolerance (T2). The start of
// a deviation is an events row with the receiver as actor; a continuing
// one only counts.
func (s *Service) Heartbeat(ctx context.Context, id string, in HeartbeatIn) (HeartbeatResult, error) {
	now := s.now()
	var res HeartbeatResult
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		locked, err := q.ReceiverForUpdate(ctx, id)
		if err != nil {
			return mapErr(err)
		}
		r := row(locked)
		rec, err := receiverFrom(&r)
		if err != nil {
			return err
		}
		tol := *rec.Config.Resolve(s.Defaults).PositionToleranceM
		res = HeartbeatResult{SeenAt: now, PositionToleranceM: tol}
		p := gen.RecordReceiverHeartbeatParams{ID: id, LastSeenAt: &now, Firmware: in.Firmware}
		if in.Position != nil {
			p.LastLatDeg, p.LastLonDeg, p.LastAltHaeM = &in.Position.LatDeg, &in.Position.LonDeg, in.Position.AltHAEM
			d, err := geodesy.DistanceM(core.LatLon{LatDeg: r.LatDeg, LonDeg: r.LonDeg},
				core.LatLon{LatDeg: in.Position.LatDeg, LonDeg: in.Position.LonDeg})
			if err != nil {
				return core.Fieldf("position", "distance from the pinned position: %v", err)
			}
			p.PositionDeviationM = &d
			res.DeviationM = &d
			if d > tol {
				p.DeviationIncrement = 1
				s.Counters.Inc(CounterPositionDeviations)
				wasWithin := r.PositionDeviationM == nil || *r.PositionDeviationM <= tol
				if wasWithin {
					if _, err := s.Audit.Record(ctx, q, audit.Event{
						Actor: audit.Actor{Type: audit.ActorReceiver, ID: id}, EntityType: entityType, EntityID: id,
						EventType: EventPositionDeviation,
						Payload:   map[string]any{"deviation_m": d, "tolerance_m": tol, "lat_deg": in.Position.LatDeg, "lon_deg": in.Position.LonDeg},
					}); err != nil {
						return err
					}
				}
			}
		}
		if err := q.RecordReceiverHeartbeat(ctx, p); err != nil {
			return err
		}
		r.LastSeenAt = &now
		if in.Position != nil {
			r.LastLatDeg, r.LastLonDeg, r.LastAltHaeM = p.LastLatDeg, p.LastLonDeg, p.LastAltHaeM
			r.PositionDeviationM = p.PositionDeviationM
			r.PositionDeviations += p.DeviationIncrement
		}
		if in.Firmware != nil {
			r.Firmware = in.Firmware
		}
		res.Receiver, err = receiverFrom(&r)
		return err
	})
	if err != nil {
		return HeartbeatResult{}, err
	}
	s.Counters.Inc(CounterHeartbeats)
	return res, nil
}

// Reproject writes the whole key set from the registry and deletes the
// entries of receivers the registry no longer holds: the repair of a lost
// or stale bucket (G-08), run at startup and periodically under an
// advisory lock.
func (s *Service) Reproject(ctx context.Context) error {
	lock, ok, err := s.DB.AdvisoryLock(ctx, pg.LockKey("rid_receiver_keys_reproject"))
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	defer func() { _ = lock.Release(context.WithoutCancel(ctx)) }()
	want := map[string]bool{}
	after := ""
	for {
		rows, err := s.DB.Queries().ListReceivers(ctx, gen.ListReceiversParams{AfterID: after, PageSize: 500})
		if err != nil {
			return err
		}
		for i := range rows {
			r := row(rows[i])
			e, err := s.entryOf(&r)
			if err != nil {
				return err
			}
			if err := s.Keys.Put(ctx, e); err != nil {
				return err
			}
			want[r.ID] = true
		}
		if len(rows) < 500 {
			break
		}
		after = rows[len(rows)-1].ID
	}
	have, err := s.Keys.Keys(ctx)
	if err != nil {
		return err
	}
	for _, id := range have {
		if !want[id] {
			if err := s.Keys.Delete(ctx, id); err != nil {
				return err
			}
			s.Counters.Inc(CounterStaleKeysDeleted)
		}
	}
	s.Counters.Inc(CounterReprojected)
	return nil
}

// RunReprojection repairs the key set at start and every interval until
// ctx ends; a failure is counted, logged at a bounded rate and retried at
// the next tick.
func (s *Service) RunReprojection(ctx context.Context, interval time.Duration, lim *logging.Limiter) {
	run := func(cause string) {
		if err := s.Reproject(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			s.Counters.Inc(CounterReprojectFailed)
			lim.Limited("rid_receiver_keys_reproject").Warn("receiver key set re-projection failed; rid-ingest keeps its last key set",
				slog.String("cause", cause), slog.String("error", err.Error()))
			return
		}
		s.logger().Debug("receiver key set re-projected", slog.String("cause", cause))
	}
	run("startup")
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run("periodic")
		}
	}
}
