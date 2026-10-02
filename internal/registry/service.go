package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/store"
)

// Counters of the registry (status line and /metrics, E-09). Each names
// one refusal, fallback or degraded state.
const (
	CounterProjectionWriteFailed = "registry_projection_write_failed" // a change rolled back because its projection write failed (SC-17 step 3)
	CounterProjectionAhead       = "registry_projection_ahead"        // a tightening change: the projection committed, the relational commit failed; a repair was requested
	CounterProjectionBehind      = "registry_projection_behind"       // a loosening change committed, its projection write failed; the stricter row stays until the repair
	CounterReprojectRetried      = "registry_reproject_retried"       // a failed re-projection retried with backoff before the periodic run
	CounterPublishFailed         = "registry_publish_failed"          // a change committed, its push failed; readers catch up on their 5 s re-read
	CounterReprojected           = "registry_reprojected"             // full re-projections written
	CounterReprojectFailed       = "registry_reproject_failed"        // a full re-projection failed; the next run repairs
	CounterReprojectSkipped      = "registry_reproject_skipped"       // another replica held the job lock
	CounterProjectionMarked      = "registry_projection_rows_marked"  // projection rows the registry does not hold, marked (in_registry false, unregistered)
	CounterExpired               = "registry_expired"                 // registrations the expiry job marked expired
	CounterExpiryFailed          = "registry_expiry_failed"           // an expiry run failed
	CounterRefused               = "registry_change_refused"          // a registration or change refused (validation, conflict, transition)
	CounterPolicyUnavailable     = "registry_policy_unavailable"      // a registration refused because no active policy was known
	CounterValidated             = "registry_validated"               // F8 entities answered
	CounterValidatedUnknown      = "registry_validated_unknown"       // F8 entities answered unknown
)

// Advisory locks. LockProjection is taken by every change that writes
// the projection and by the full re-projection from its relational read
// to its projection write, so a change waits for a running
// re-projection and is never overwritten by its older read (SC-17 step
// 5). The job locks keep two api replicas from running one job at once.
const (
	LockProjection   = "registry_projection"
	LockReprojectJob = "registry_reprojection_job"
	LockExpiryJob    = "registry_expiry_job"
)

// SlugProjection is the problem slug of a change refused because the
// projection could not be written.
const SlugProjection = "projection_unavailable"

// ErrProjection marks a change rolled back because its projection write
// failed.
var ErrProjection = errors.New("registry projection not written")

// MaxPageSize bounds a registry page.
const MaxPageSize = 500

// expiryBatch bounds the registrations one expiry run marks (E-10); the
// next run takes the rest.
const expiryBatch = 500

// PatternSource returns the active policy's registration-number pattern
// and whether a policy is known.
type PatternSource func() (string, bool)

// Publisher announces a new registry version after a commit: subject
// registry.v1.changed and KV registry_version once the bus lands
// (WP-10). Until then api publishes nowhere, and the readers' periodic
// re-read carries every change (G-08).
type Publisher interface {
	PublishRegistryVersion(ctx context.Context, version int64) error
}

// NopPublisher publishes nowhere.
type NopPublisher struct{}

// PublishRegistryVersion does nothing.
func (NopPublisher) PublishRegistryVersion(context.Context, int64) error { return nil }

// Service is the registry (api only).
type Service struct {
	Store      Store
	Projection Projection
	Sealer     *pii.Sealer
	Hasher     *Hasher
	Pattern    PatternSource
	Publisher  Publisher
	Counters   *core.Counters
	Logger     *slog.Logger
	// MTOMBandsG are the upper bounds, in grams and ascending, of the
	// MTOM bands F8 answers (REGISTRY_MTOM_BANDS_G).
	MTOMBandsG []int
	// Now is the clock; nil is time.Now.
	Now func() time.Time

	repairOnce sync.Once
	repair     chan struct{}
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Service) count(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

func (s *Service) repairs() chan struct{} {
	s.repairOnce.Do(func() { s.repair = make(chan struct{}, 1) })
	return s.repair
}

// RequestRepair asks the job loop for a full re-projection now.
func (s *Service) RequestRepair() {
	select {
	case s.repairs() <- struct{}{}:
	default:
	}
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validator is regnum's validator under the active policy's pattern
// (G-07, INV-03).
func (s *Service) validator() (*regnum.Validator, error) {
	if s.Pattern == nil {
		return regnum.NewValidator("")
	}
	p, ok := s.Pattern()
	if !ok {
		s.count(CounterPolicyUnavailable)
		return nil, httpx.Refuse(http.StatusServiceUnavailable, "policy_unavailable",
			"no active policy is loaded yet, so the registration-number format is unknown; retry shortly")
	}
	return regnum.NewValidator(p)
}

// changeSet collects the projection rows of one change.
type changeSet struct {
	version int64
	at      time.Time
	ops     []ProjectedOperator
	uas     []ProjectedUAS
	// loosening marks a change that can make an aircraft or an operator
	// look more valid: a registration, or a status becoming active.
	loosening bool
}

// change runs fn in one relational transaction that holds
// LockProjection and numbers the change, and writes the projection rows
// fn collected in the order that fails safe (G-08):
//
//   - a tightening or neutral change (suspend, revoke, expire, edit)
//     writes and commits the projection before the relational commit. A
//     failed projection write rolls the change back and is a 503 naming
//     the cause (SC-17 step 3). If the relational commit then fails, the
//     projection is stricter than the registry: counted, and a repair is
//     requested at once.
//   - a loosening change (a registration, a status becoming active)
//     commits the relational row first and writes the projection after.
//     If the relational commit fails, the projection never saw the
//     change; if the projection write fails, the projection keeps the
//     stricter state, the change stands, and a repair is requested
//     (retried with backoff). Either way no projection row says active
//     while the registry does not.
//
// A late loosening write never replaces a newer row (registry_version),
// so a change committed after it is not undone. After the projection is
// written the new version is published.
func (s *Service) change(ctx context.Context, fn func(tx Tx, cs *changeSet) error) error {
	var projected bool
	var cs *changeSet
	err := s.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, LockProjection); err != nil {
			return err
		}
		v, err := tx.NextVersion(ctx)
		if err != nil {
			return err
		}
		cs = &changeSet{version: v, at: s.now()}
		if err := fn(tx, cs); err != nil {
			return err
		}
		if len(cs.ops) == 0 && len(cs.uas) == 0 || cs.loosening {
			return nil
		}
		if err := s.writeProjection(ctx, cs); err != nil {
			s.count(CounterProjectionWriteFailed)
			logging.Error(ctx, s.logger(), "registry change rolled back: the projection was not written", err,
				slog.Int64("registry_version", cs.version))
			return projectionRefusal(err)
		}
		projected = true
		return nil
	})
	if err != nil {
		if projected {
			s.count(CounterProjectionAhead)
			logging.Error(ctx, s.logger(), "registry change not committed after its projection was; re-projecting now", err,
				slog.Int64("registry_version", cs.version))
			s.RequestRepair()
		}
		return s.refused(err)
	}
	if cs.loosening && (len(cs.ops) > 0 || len(cs.uas) > 0) {
		if err := s.writeProjection(ctx, cs); err != nil {
			s.count(CounterProjectionBehind)
			logging.Error(ctx, s.logger(), "registry change committed but not projected; the projection keeps the stricter state until the repair", err,
				slog.Int64("registry_version", cs.version))
			s.RequestRepair()
			return nil
		}
		projected = true
	}
	if projected {
		s.publish(ctx, cs.version)
	}
	return nil
}

func (s *Service) writeProjection(ctx context.Context, cs *changeSet) error {
	ptx, err := s.Projection.Begin(ctx)
	if err != nil {
		return err
	}
	if err := ptx.UpsertOperators(ctx, cs.ops, cs.at, false); err != nil {
		ptx.Rollback(ctx)
		return err
	}
	if err := ptx.UpsertUAS(ctx, cs.uas, cs.at, false); err != nil {
		ptx.Rollback(ctx)
		return err
	}
	return ptx.Commit(ctx)
}

func (s *Service) publish(ctx context.Context, version int64) {
	pub := s.Publisher
	if pub == nil {
		pub = NopPublisher{}
	}
	if err := pub.PublishRegistryVersion(ctx, version); err != nil {
		s.count(CounterPublishFailed)
		logging.Error(ctx, s.logger(), "registry change committed but not announced; readers apply it on their next re-read", err,
			slog.Int64("registry_version", version))
	}
}

// refused counts a refusal (a problem below 500) and passes err on.
func (s *Service) refused(err error) error {
	if p := httpx.ProblemFromError(err); p.Status < http.StatusInternalServerError {
		s.count(CounterRefused)
	}
	return err
}

// projectionRefusal is the 503 of a change whose projection write
// failed. The detail names the cause (SQLSTATE and constraint, or an
// unreachable database) without echoing the driver's message.
func projectionRefusal(err error) error {
	reason := "the telemetry database could not be reached"
	if state := store.SQLState(err); state != "" {
		reason = "the telemetry database refused the write (SQLSTATE " + state + ")"
		if c := store.Constraint(err); c != "" {
			reason += " on " + c
		}
	}
	return errors.Join(ErrProjection, httpx.Refuse(http.StatusServiceUnavailable, SlugProjection,
		"the registry projection could not be written, so the change was rolled back: "+reason))
}

func notFound(entity, id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such "+entity, core.Fieldf("id", "%s %q is not registered", entity, id))
}

func conflict(detail string, fe *core.FieldError) error {
	return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, detail, fe)
}

var errRevokedFinal = conflict("a revoked registration is final", core.Fieldf("status", "revoked; register again instead"))

// Sealing. Each personal value is bound to its table, row and column, so
// a value copied into another row or column does not open.

func aad(table, id, column string) []byte { return []byte(table + ":" + id + ":" + column) }

func (s *Service) seal(table, id, column, value string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	return s.Sealer.Seal([]byte(value), aad(table, id, column))
}

func (s *Service) open(keyID, table, id, column string, sealed []byte) (string, error) {
	if sealed == nil {
		return "", nil
	}
	b, err := s.Sealer.Open(keyID, sealed, aad(table, id, column))
	if err != nil {
		return "", fmt.Errorf("%s.%s of %s: %w", table, column, id, err)
	}
	return string(b), nil
}

const tableOperators = "uas_operators"

func (s *Service) sealOperator(id string, p *OperatorPII) (SealedOperator, error) {
	out := SealedOperator{KeyID: s.Sealer.KeyID()}
	for _, f := range []struct {
		column string
		value  string
		dst    *[]byte
	}{
		{"full_name", p.FullName, &out.FullName},
		{"legal_name", p.LegalName, &out.LegalName},
		{"date_of_birth", p.DateOfBirth, &out.DateOfBirth},
		{"legal_identification_number", p.LegalIdentificationNumber, &out.LegalIdentificationNumber},
		{"postal_address", p.PostalAddress, &out.PostalAddress},
		{"contact_email", p.ContactEmail, &out.ContactEmail},
		{"contact_phone", p.ContactPhone, &out.ContactPhone},
		{"insurance_policy_number", p.InsurancePolicyNumber, &out.InsurancePolicyNumber},
	} {
		b, err := s.seal(tableOperators, id, f.column, f.value)
		if err != nil {
			return SealedOperator{}, err
		}
		*f.dst = b
	}
	return out, nil
}

func (s *Service) openOperator(r *OperatorRecord) (OperatorPII, error) {
	var out OperatorPII
	sd := r.Sealed
	for _, f := range []struct {
		column string
		sealed []byte
		dst    *string
	}{
		{"full_name", sd.FullName, &out.FullName},
		{"legal_name", sd.LegalName, &out.LegalName},
		{"date_of_birth", sd.DateOfBirth, &out.DateOfBirth},
		{"legal_identification_number", sd.LegalIdentificationNumber, &out.LegalIdentificationNumber},
		{"postal_address", sd.PostalAddress, &out.PostalAddress},
		{"contact_email", sd.ContactEmail, &out.ContactEmail},
		{"contact_phone", sd.ContactPhone, &out.ContactPhone},
		{"insurance_policy_number", sd.InsurancePolicyNumber, &out.InsurancePolicyNumber},
	} {
		v, err := s.open(sd.KeyID, tableOperators, r.ID, f.column, f.sealed)
		if err != nil {
			return OperatorPII{}, err
		}
		*f.dst = v
	}
	return out, nil
}

// checkPurpose refuses a personal-data read without a purpose (CLAUDE.md
// rule 6).
func checkPurpose(purpose string) error {
	if err := text("purpose", purpose, maxNameLen, true); err != nil {
		return httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "a personal-data read needs a purpose",
			core.Fieldf("purpose", "required: say why the personal data is read"))
	}
	return nil
}
