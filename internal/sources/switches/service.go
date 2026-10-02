package switches

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"time"

	"github.com/rootxkit/uspace-core/core"
	coresources "github.com/rootxkit/uspace-core/sources"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/sources"
	"github.com/rootxkit/uspace-authority/internal/store"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Events and entity of a switch (internal/audit catalogue).
const (
	EventDisabled     = audit.EventSourceDisabled
	EventEnabled      = audit.EventSourceEnabled
	EventEpochStarted = audit.EventSourceControlEpochStarted
	entityType        = "source"
)

// Problem slug and counters (E-09).
const (
	SlugUnavailable = "source_control_unavailable"

	CounterSwitched         = "switched"
	CounterUnchanged        = "switch_unchanged"
	CounterStoreRefused     = "store_write_refused"
	CounterTooLarge         = "state_too_large"
	CounterPushFailed       = "push_failed"
	CounterRepublished      = "republished"
	CounterRepublishNoop    = "republish_nothing_to_do"
	CounterRepublishFailed  = "republish_failed"
	CounterEpochStarted     = "epoch_started"
	CounterBucketMalformed  = "bucket_malformed"
	CounterRepairAfterAbort = "repair_after_failed_commit"
)

// lockKey serialises every writer of the state, switches and
// republishes alike, so two api replicas never write back a state the
// other has just replaced (B-09).
var lockKey = pgstore.LockKey("source_controls")

var instancePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`)

// StateStore is where the state is published: KV bucket source_control,
// key "state".
type StateStore interface {
	Read(ctx context.Context) (raw []byte, published bool, err error)
	Put(ctx context.Context, raw []byte) error
}

// KV is the StateStore of the bus.
type KV struct{ Source sources.Source }

// Read reads the stored document.
func (k KV) Read(ctx context.Context) ([]byte, bool, error) { return k.Source.Read(ctx) }

// Put writes raw, bounded by the source's timeout.
func (k KV) Put(ctx context.Context, raw []byte) error {
	if k.Source.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, k.Source.Timeout)
		defer cancel()
	}
	kv, err := k.Source.Open(ctx)
	if err != nil {
		return err
	}
	_, err = kv.Put(ctx, sources.StateKey, raw)
	return err
}

// Service is api's writer of the switches (U-15).
type Service struct {
	DB    *pgstore.DB
	Audit *audit.Writer
	Store StateStore
	// Push sends the state on Subject after a commit; nil sends nothing.
	Push    bus.Publisher
	Subject string
	// DefaultDeny travels in the state (SOURCES_DEFAULT_DENY).
	DefaultDeny bool
	// MaxBytes is the bucket's value bound
	// (SOURCE_CONTROL_MAX_VALUE_BYTES); Bucket names it in a refusal.
	MaxBytes int
	Bucket   string
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter
	Now      func() time.Time
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

// Result is the outcome of a switch.
type Result struct {
	Control sources.Control
	// Changed is false when the switch already held the state.
	Changed bool
	Epoch   string
	Version uint64
}

func controlOf(r pggen.SourceControl) sources.Control {
	return sources.Control{
		SourceType: r.SourceType, InstanceID: r.InstanceID, Enabled: r.Enabled, Reason: r.Reason,
		Actor: r.Actor, ChangedAt: r.ChangedAt.UTC(), Version: uint64(r.Version),
	}
}

// document builds the state from the database inside q's transaction.
func (s *Service) document(ctx context.Context, q *pggen.Queries) (sources.Document, error) {
	meta, err := q.SourceControlEpoch(ctx)
	if err != nil {
		return sources.Document{}, err
	}
	rows, err := q.ListSourceControls(ctx)
	if err != nil {
		return sources.Document{}, err
	}
	d := sources.Document{Epoch: meta.Epoch, Version: uint64(meta.Version), DefaultDeny: s.DefaultDeny, Controls: make([]sources.Control, 0, len(rows))}
	for _, r := range rows {
		d.Controls = append(d.Controls, controlOf(r))
	}
	return d, nil
}

// encode is d as stored, refused past the bucket's bound naming it.
func (s *Service) encode(d sources.Document) ([]byte, error) {
	raw, err := sources.Encode(d, s.now())
	if err != nil {
		return nil, err
	}
	if s.MaxBytes > 0 && len(raw) > s.MaxBytes {
		s.Counters.Inc(CounterTooLarge)
		return nil, core.Fieldf("controls", "the source-control state would be %d bytes, over the limit of %d bytes of bucket %s (SOURCE_CONTROL_MAX_VALUE_BYTES); nothing was changed",
			len(raw), s.MaxBytes, s.Bucket)
	}
	return raw, nil
}

func (s *Service) unavailable(err error) error {
	s.Counters.Inc(CounterStoreRefused)
	logging.Error(context.Background(), s.logger(), "source-control state not written; switch refused", err)
	return httpx.Refuse(http.StatusServiceUnavailable, SlugUnavailable,
		"the switch state cannot be published now; nothing was changed, retry later")
}

// Validate refuses an unknown type or a malformed instance id.
func Validate(sourceType string, instanceID *string, reason string) error {
	var errs []error
	if !slices.Contains(sources.Types, sourceType) {
		errs = append(errs, core.Fieldf("source_type", "must be one of %v", sources.Types))
	}
	if instanceID != nil && !instancePattern.MatchString(*instanceID) {
		errs = append(errs, core.Fieldf("instance_id", "must match %s", instancePattern))
	}
	if reason == "" || len(reason) > 500 {
		errs = append(errs, core.Fieldf("reason", "1 to 500 characters"))
	}
	return errors.Join(errs...)
}

// Switch sets a type (instanceID nil) or an instance on or off. In one
// transaction under the advisory lock: the row, its events row, then the
// KV write of the whole state with the next version; a KV failure rolls
// everything back and is refused with 503 (B-09, SC-08 step 8). After
// the commit the state is pushed. A switch to the state held writes
// nothing.
func (s *Service) Switch(ctx context.Context, actor audit.Actor, sourceType string, instanceID *string, enabled bool, reason string) (Result, error) {
	if err := Validate(sourceType, instanceID, reason); err != nil {
		return Result{}, err
	}
	var res Result
	var published []byte
	written := false
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockKey); err != nil {
			return err
		}
		meta, err := q.SourceControlEpoch(ctx)
		if err != nil {
			return err
		}
		cur, err := q.SourceControlFor(ctx, pggen.SourceControlForParams{SourceType: sourceType, InstanceID: instanceID})
		found := err == nil
		if err != nil && !store.IsNoRows(err) {
			return err
		}
		if found && cur.Enabled == enabled {
			res = Result{Control: controlOf(cur), Epoch: meta.Epoch, Version: uint64(meta.Version)}
			return nil
		}
		v, err := q.NextSourceControlVersion(ctx)
		if err != nil {
			return err
		}
		now := s.now()
		row := pggen.SourceControl{SourceType: sourceType, InstanceID: instanceID, Enabled: enabled, Reason: reason,
			Actor: actor.ID, ChangedAt: now, Version: v, Epoch: meta.Epoch}
		if found {
			err = q.UpdateSourceControl(ctx, pggen.UpdateSourceControlParams{Enabled: enabled, Reason: reason, Actor: actor.ID,
				ChangedAt: now, Version: v, Epoch: meta.Epoch, SourceType: sourceType, InstanceID: instanceID})
		} else {
			err = q.InsertSourceControl(ctx, pggen.InsertSourceControlParams{SourceType: sourceType, InstanceID: instanceID,
				Enabled: enabled, Reason: reason, Actor: actor.ID, ChangedAt: now, Version: v, Epoch: meta.Epoch})
		}
		if err != nil {
			return err
		}
		if err := q.SetSourceControlVersion(ctx, v); err != nil {
			return err
		}
		event, entity := EventEnabled, sourceType+"/*"
		if !enabled {
			event = EventDisabled
		}
		if instanceID != nil {
			entity = sourceType + "/" + *instanceID
		}
		payload := map[string]any{"reason": reason, "enabled": enabled, "version": v, "epoch": meta.Epoch, "previous": nil}
		if found {
			payload["previous"] = map[string]any{"enabled": cur.Enabled, "actor": cur.Actor, "reason": cur.Reason}
		}
		if _, err := s.Audit.Record(ctx, q, audit.Event{Actor: actor, EntityType: entityType, EntityID: entity, EventType: event, Payload: payload}); err != nil {
			return err
		}
		doc, err := s.document(ctx, q)
		if err != nil {
			return err
		}
		raw, err := s.encode(doc)
		if err != nil {
			return err
		}
		if err := s.Store.Put(ctx, raw); err != nil {
			return s.unavailable(err)
		}
		written, published = true, raw
		res = Result{Control: controlOf(row), Changed: true, Epoch: meta.Epoch, Version: uint64(v)}
		return nil
	})
	if err != nil {
		if written {
			// The bucket holds a state the database did not commit: put
			// the database's state back over it before answering.
			s.Counters.Inc(CounterRepairAfterAbort)
			if _, rerr := s.Republish(context.WithoutCancel(ctx)); rerr != nil {
				logging.Error(ctx, s.logger(), "source-control state not repaired after a failed commit; the periodic republish retries", rerr)
			}
		}
		return Result{}, err
	}
	if !res.Changed {
		s.Counters.Inc(CounterUnchanged)
		return res, nil
	}
	s.Counters.Inc(CounterSwitched)
	s.push(published)
	return res, nil
}

// push sends the state on the push subject; a failure is counted and
// repaired by the followers' watch and re-read.
func (s *Service) push(raw []byte) {
	if s.Push == nil || s.Subject == "" || raw == nil {
		return
	}
	if err := s.Push.Publish(s.Subject, raw); err != nil {
		s.Counters.Inc(CounterPushFailed)
		if s.Limiter != nil {
			s.Limiter.Limited("source_control_push").Warn("source-control state not pushed; followers take it from the bucket",
				slog.String("error", err.Error()))
		}
	}
}

func newEpoch() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Republish writes the database's state to the bucket when the bucket
// does not hold it (a lost or corrupt bucket, a changed default), and
// reports whether it wrote. A bucket ahead of the database within the
// same epoch (a database restored from a backup, or a commit that failed
// after its write) starts a new epoch, audited, so followers take the
// database's state rather than ignore it as older (B-09).
func (s *Service) Republish(ctx context.Context) (bool, error) {
	var raw []byte
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockKey); err != nil {
			return err
		}
		doc, err := s.document(ctx, q)
		if err != nil {
			return err
		}
		have, published, err := s.Store.Read(ctx)
		if err != nil {
			return err
		}
		var held sources.Document
		heldOK := false
		if published {
			if held, err = sources.Decode(have); err != nil {
				s.Counters.Inc(CounterBucketMalformed)
				logging.Error(ctx, s.logger(), "source-control bucket holds a malformed state; overwriting it", err)
			} else {
				heldOK = true
			}
		}
		switch {
		case heldOK && held.Same(doc):
			return nil
		case heldOK && held.Epoch == doc.Epoch && held.Version > doc.Version:
			epoch, err := newEpoch()
			if err != nil {
				return err
			}
			if err := q.StartSourceControlEpoch(ctx, pggen.StartSourceControlEpochParams{Epoch: epoch, Version: int64(doc.Version)}); err != nil {
				return err
			}
			if _, err := s.Audit.Record(ctx, q, audit.Event{
				Actor: audit.SystemActor("api"), EntityType: entityType, EntityID: "*", EventType: EventEpochStarted,
				Payload: map[string]any{"from_epoch": doc.Epoch, "to_epoch": epoch, "bucket_version": held.Version, "database_version": doc.Version},
			}); err != nil {
				return err
			}
			s.Counters.Inc(CounterEpochStarted)
			s.logger().Warn("source-control bucket ahead of the database (a restored database or an aborted commit): new epoch",
				slog.String("from_epoch", doc.Epoch), slog.String("to_epoch", epoch), slog.Uint64("bucket_version", held.Version),
				slog.Uint64("database_version", doc.Version))
			doc.Epoch = epoch
		case heldOK && held.Epoch == doc.Epoch && held.Version == doc.Version && !held.SameContent(doc):
			// The same version with other content (a changed default):
			// followers would ignore it, so it takes the next version.
			v, err := q.NextSourceControlVersion(ctx)
			if err != nil {
				return err
			}
			if err := q.SetSourceControlVersion(ctx, v); err != nil {
				return err
			}
			doc.Version = uint64(v)
		}
		if raw, err = s.encode(doc); err != nil {
			return err
		}
		return s.Store.Put(ctx, raw)
	})
	if err != nil {
		s.Counters.Inc(CounterRepublishFailed)
		return false, err
	}
	if raw == nil {
		s.Counters.Inc(CounterRepublishNoop)
		return false, nil
	}
	s.Counters.Inc(CounterRepublished)
	s.push(raw)
	return true, nil
}

// RunRepublish republishes at start and every interval until ctx ends; a
// failure is counted, logged at a bounded rate and retried at the next
// tick.
func (s *Service) RunRepublish(ctx context.Context, interval time.Duration) {
	run := func(cause string) {
		wrote, err := s.Republish(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			if s.Limiter != nil {
				s.Limiter.Limited("source_control_republish").Warn("source-control state not republished; retrying",
					slog.String("cause", cause), slog.String("error", err.Error()))
			}
		case wrote:
			s.logger().Info("source-control state republished from the database", slog.String("cause", cause))
		}
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

// Overview is the state as the database holds it.
func (s *Service) Overview(ctx context.Context) (sources.Document, error) {
	var d sources.Document
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		var err error
		d, err = s.document(ctx, q)
		return err
	})
	if err != nil {
		return sources.Document{}, fmt.Errorf("source controls: %w", err)
	}
	return d, nil
}

// Decide is the decision of the state d for one source.
func Decide(d sources.Document, sourceType string, instanceID *string) coresources.Decision {
	return d.State().Query(sourceType, instanceID)
}

// NewService is api's Service on its bus under its configuration.
func NewService(db *pgstore.DB, w *audit.Writer, bp *bus.Process, c config.Bus, sc config.Sources, logger *slog.Logger, lim *logging.Limiter) *Service {
	return &Service{
		DB: db, Audit: w, Store: KV{Source: sources.SourceOf(bp, c)}, Push: bp.NC, Subject: c.SourceControlSubject,
		DefaultDeny: sc.SourcesDefaultDeny, MaxBytes: c.SourceControlMaxValueBytes, Bucket: c.SourceControlBucket,
		Counters: &core.Counters{}, Logger: logger, Limiter: lim,
	}
}
