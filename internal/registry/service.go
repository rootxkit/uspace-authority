package registry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/pii"
)

// Counters of the registry (status line and /metrics, E-09). Each names
// one refusal, fallback or degraded state.
const (
	CounterExpired           = "registry_expired"            // registrations the expiry job marked expired
	CounterExpiryFailed      = "registry_expiry_failed"      // an expiry run failed
	CounterRefused           = "registry_change_refused"     // a registration or change refused (validation, conflict, transition)
	CounterPolicyUnavailable = "registry_policy_unavailable" // a registration refused because no active policy was known
)

// LockExpiryJob keeps two api replicas from running the expiry job at
// once.
const LockExpiryJob = "registry_expiry_job"

// MaxPageSize bounds a registry page.
const MaxPageSize = 500

// expiryBatch bounds the registrations one expiry run marks (E-10); the
// next run takes the rest.
const expiryBatch = 500

// PatternSource returns the active policy's registration-number pattern
// and whether a policy is known.
type PatternSource func() (string, bool)

// Service is the registry (api only).
type Service struct {
	Store    Store
	Sealer   *pii.Sealer
	Hasher   *Hasher
	Pattern  PatternSource
	Counters *core.Counters
	Logger   *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
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

// changeSet is one numbered change.
type changeSet struct {
	version int64
	at      time.Time
}

// change runs fn in one relational transaction numbered by
// registry_version_seq.
func (s *Service) change(ctx context.Context, fn func(tx Tx, cs *changeSet) error) error {
	err := s.Store.InTx(ctx, func(tx Tx) error {
		v, err := tx.NextVersion(ctx)
		if err != nil {
			return err
		}
		return fn(tx, &changeSet{version: v, at: s.now()})
	})
	if err != nil {
		return s.refused(err)
	}
	return nil
}

// refused counts a refusal (a problem below 500) and passes err on.
func (s *Service) refused(err error) error {
	if p := httpx.ProblemFromError(err); p.Status < http.StatusInternalServerError {
		s.count(CounterRefused)
	}
	return err
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
