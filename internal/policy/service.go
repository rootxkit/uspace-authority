package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the policy component (status line and /metrics).
const (
	CounterPublishFailed  = "policy_publish_failed"  // activated, but the publish to followers failed; they catch up on re-read
	CounterRefreshFailed  = "policy_refresh_failed"  // a follower's re-read failed; it keeps the last policy
	CounterOlderIgnored   = "policy_older_ignored"   // a follower was offered a lower version and kept its own
	CounterInvalidRefused = "policy_invalid_refused" // a follower was offered a policy that does not validate
	CounterApplied        = "policy_applied"         // a follower applied a higher version
)

// MaxNoteLen bounds Policy.Note.
const MaxNoteLen = 1000

// Publisher announces an activated policy to the processes that follow
// it: KV policy and ctl.policy once the bus lands (WP-10). Until then
// api publishes to its own Follower, and tests use a recorder.
type Publisher interface {
	PublishPolicy(ctx context.Context, p Policy) error
}

// NopPublisher publishes nowhere.
type NopPublisher struct{}

// PublishPolicy does nothing.
func (NopPublisher) PublishPolicy(context.Context, Policy) error { return nil }

// Errors of the service, mapped onto problems by the handler.
var (
	ErrNotFound = errors.New("no such policy version")
	ErrNotNewer = errors.New("only a version newer than the active one can be activated")
)

// Service stores, activates and publishes policy versions (api only).
type Service struct {
	DB        *pg.DB
	Audit     *audit.Writer
	Publisher Publisher
	Logger    *slog.Logger
	Counters  *core.Counters
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// lockName serialises version allocation and activation.
const lockName = "authority_policy"

// Active is the active version.
func (s *Service) Active(ctx context.Context) (Policy, error) {
	r, err := s.DB.Queries().ActivePolicy(ctx)
	if store.IsNoRows(err) {
		return Policy{}, fmt.Errorf("no active policy: %w", ErrNotFound)
	}
	if err != nil {
		return Policy{}, fmt.Errorf("read active policy: %w", err)
	}
	return fromRow(r), nil
}

// Create validates t and stores it as the next version, inactive, with
// a policy_created event in the same transaction.
func (s *Service) Create(ctx context.Context, t Thresholds, note string, actor audit.Actor) (Policy, error) {
	errs := []error{t.Validate()}
	if len(note) > MaxNoteLen {
		errs = append(errs, core.Fieldf("note", "longer than %d bytes", MaxNoteLen))
	}
	if err := errors.Join(errs...); err != nil {
		return Policy{}, err
	}
	var out Policy
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, pg.LockKey(lockName)); err != nil {
			return err
		}
		last, err := q.MaxPolicyVersion(ctx)
		if err != nil {
			return err
		}
		r, err := q.InsertPolicy(ctx, insertParams(last+1, t, note, actor.ID, s.now()))
		if err != nil {
			return err
		}
		out = fromRow(r)
		_, err = s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: "authority_policy", EntityID: fmt.Sprint(out.Version),
			EventType: audit.EventPolicyCreated, Payload: map[string]any{"version": out.Version, "thresholds": t, "note": note},
		})
		return err
	})
	if err != nil {
		return Policy{}, fmt.Errorf("create policy: %w", err)
	}
	return out, nil
}

// Activate makes version the active policy, records policy_activated in
// the same transaction, and publishes it after the commit. Only a
// version newer than the active one is accepted: followers apply only a
// higher version, so a rollback is a new version with the old values.
// A failed publish does not undo the activation; it is counted and
// logged, and followers catch up on their periodic re-read (G-08).
func (s *Service) Activate(ctx context.Context, version int64, actor audit.Actor) (Policy, error) {
	var out Policy
	var previous int64
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, pg.LockKey(lockName)); err != nil {
			return err
		}
		if _, err := q.PolicyByVersion(ctx, version); err != nil {
			if store.IsNoRows(err) {
				return ErrNotFound
			}
			return err
		}
		active, err := q.ActivePolicy(ctx)
		switch {
		case store.IsNoRows(err):
		case err != nil:
			return err
		default:
			previous = active.Version
		}
		if version <= previous {
			return ErrNotNewer
		}
		if err := q.DeactivatePolicies(ctx); err != nil {
			return err
		}
		at, by := s.now(), actor.ID
		r, err := q.ActivatePolicy(ctx, gen.ActivatePolicyParams{ActivatedAt: &at, ActivatedBy: &by, Version: version})
		if err != nil {
			return err
		}
		out = fromRow(r)
		_, err = s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: "authority_policy", EntityID: fmt.Sprint(version),
			EventType: audit.EventPolicyActivated, Payload: map[string]any{"version": version, "previous_version": previous},
		})
		return err
	})
	if err != nil {
		return Policy{}, refusal(err, version, previous)
	}
	if err := s.publisher().PublishPolicy(ctx, out); err != nil {
		if s.Counters != nil {
			s.Counters.Inc(CounterPublishFailed)
		}
		logging.Error(ctx, s.logger(), "policy activated but not published; followers apply it on their next re-read", err,
			slog.Int64("policy_version", version))
	}
	return out, nil
}

func refusal(err error, version, previous int64) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, ErrNotFound.Error(),
			core.Fieldf("version", "%d does not exist", version))
	case errors.Is(err, ErrNotNewer):
		return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, ErrNotNewer.Error(),
			core.Fieldf("version", "%d is not newer than the active version %d; create a new version to roll back", version, previous))
	default:
		return fmt.Errorf("activate policy %d: %w", version, err)
	}
}

func (s *Service) publisher() Publisher {
	if s.Publisher == nil {
		return NopPublisher{}
	}
	return s.Publisher
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}
