package regportal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Application states (registry_applications.state).
const (
	StateUnverified  = "unverified"
	StateSubmitted   = "submitted"
	StateUnderReview = "under_review"
	StateApproved    = "approved"
	StateRefused     = "refused"
)

// maxReasonRunes bounds a refusal reason (the contract's maxLength).
const maxReasonRunes = 500

// Applicant is an application's content: the 2019/947 Art. 14(2) field
// set without a number. It is sealed whole at rest.
type Applicant struct {
	OperatorType           string               `json:"operator_type"`
	PII                    registry.OperatorPII `json:"pii"`
	CompetencyConfirmation bool                 `json:"competency_confirmation"`
	Authorisations         json.RawMessage      `json:"authorisations,omitempty"`
}

// Application is an application without its content.
type Application struct {
	ID              string
	State           string
	OperatorType    string
	Lang            string
	SubmittedAt     time.Time
	VerifyExpiresAt time.Time
	VerifiedAt      *time.Time
	RegistrarID     string
	ReviewStartedAt *time.Time
	DecidedAt       *time.Time
	RefusalReason   string
	IssuedNumber    string
	OperatorID      string
	ValidUntil      *time.Time
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func applicationOf(r *gen.RegistryApplication) Application {
	return Application{
		ID: r.ID, State: r.State, OperatorType: r.OperatorType, Lang: r.Lang, SubmittedAt: r.SubmittedAt,
		VerifyExpiresAt: r.VerifyExpiresAt, VerifiedAt: r.VerifiedAt, RegistrarID: deref(r.RegistrarID),
		ReviewStartedAt: r.ReviewStartedAt, DecidedAt: r.DecidedAt, RefusalReason: deref(r.RefusalReason),
		IssuedNumber: deref(r.IssuedNumber), OperatorID: deref(r.OperatorID), ValidUntil: r.ValidUntil,
	}
}

func payloadAAD(id string) string { return applicationTableName + ":" + id + ":payload" }
func secretAAD(id string) string  { return applicationTableName + ":" + id + ":secret" }

// link is the portal page a mailed link opens; the token travels in the
// fragment, which a browser never sends to a server.
func (s *Service) link(path, token string) string {
	return strings.TrimSuffix(s.Config.PortalURL, "/") + path + "#token=" + url.QueryEscape(token)
}

func (s *Service) applicationToken(id string, exp time.Time) (string, error) {
	return s.Signer.Sign(Claims{Purpose: PurposeApplication, Subject: id, Exp: exp.Unix()})
}

// statusLinkExpiry is how long an application's link keeps showing its
// state: until the application is purged.
func (s *Service) statusLinkExpiry(from time.Time) time.Time {
	return from.Add(s.Config.Retain + s.Config.VerifyTTL)
}

func notFoundApplication() error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such application, or the link does not verify")
}

// Submit receives an application: checked whole before anything is
// stored (the registry's own rules), the client address's budget spent,
// the content sealed, the verification e-mail queued and the events row
// written in one transaction. The e-mail is sent after the commit.
func (s *Service) Submit(ctx context.Context, in Applicant, lang, remoteIP string) (Application, error) {
	if err := s.needApplications(); err != nil {
		return Application{}, err
	}
	var errs []error
	if !validLang(lang) {
		errs = append(errs, core.Fieldf("lang", "must be en or ka"))
	}
	if in.Authorisations == nil {
		in.Authorisations = json.RawMessage("[]")
	}
	if err := registry.CheckApplicant(in.OperatorType, in.PII, in.Authorisations, time.Now().UTC()); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return Application{}, err
	}
	id, err := newID()
	if err != nil {
		return Application{}, err
	}
	sealed, err := s.seal(payloadAAD(id), in)
	if err != nil {
		return Application{}, err
	}
	ipHash := s.Signer.Hash("ip", remoteIP)
	var out Application
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := spend(ctx, q, BucketApplication, ipHash, s.Config.ApplicationsIP, s.Config.Window); err != nil {
			return err
		}
		r, err := q.InsertApplication(ctx, gen.InsertApplicationParams{
			ID: id, OperatorType: in.OperatorType, Lang: lang, PiiKeyID: s.Sealer.KeyID(), PayloadEnc: sealed,
			RemoteIpHash: ipHash, VerifyTtlS: s.Config.VerifyTTL.Seconds(),
		})
		if err != nil {
			return err
		}
		tok, err := s.applicationToken(id, s.statusLinkExpiry(r.SubmittedAt))
		if err != nil {
			return err
		}
		if err := s.queueMail(ctx, q, MailVerify, lang, id, Message{To: in.PII.ContactEmail, Vars: map[string]string{
			"link": s.link("/applications/"+id, tok), "expires": stamp(r.VerifyExpiresAt),
		}}); err != nil {
			return err
		}
		if err := s.record(ctx, q, audit.Event{Actor: applicantActor(), EntityType: applicationTableName, EntityID: id,
			EventType: audit.EventRegistryApplicationSubmitted,
			Payload:   map[string]any{"operator_type": in.OperatorType, "lang": lang, "remote_ip_hash": ipHash}}); err != nil {
			return err
		}
		out = applicationOf(&r)
		return nil
	})
	if err != nil {
		return Application{}, s.budget(err)
	}
	s.count(CounterSubmitted)
	return out, nil
}

// budget counts a spent budget and passes every error on.
func (s *Service) budget(err error) error {
	var be *BudgetSpentError
	if errors.As(err, &be) {
		s.count(CounterBudgetSpent)
	}
	return err
}

// tokenFor verifies an application link and that it names id; expiry by
// the database clock.
func (s *Service) tokenFor(ctx context.Context, q *gen.Queries, id, tok string) error {
	c, err := s.Signer.Verify(tok, PurposeApplication)
	if err != nil || c.Subject != id {
		s.count(CounterTokenRefused)
		return notFoundApplication()
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return err
	}
	if !now.Before(c.Expires()) {
		s.count(CounterTokenRefused)
		return notFoundApplication()
	}
	return nil
}

func (s *Service) byID(ctx context.Context, q *gen.Queries, id string) (gen.RegistryApplication, error) {
	r, err := q.ApplicationByID(ctx, id)
	if store.IsNoRows(err) {
		return gen.RegistryApplication{}, notFoundApplication()
	}
	return r, err
}

// Status answers an application's state to its link.
func (s *Service) Status(ctx context.Context, id, tok string) (Application, error) {
	if err := s.needApplications(); err != nil {
		return Application{}, err
	}
	q := s.DB.Queries()
	if err := s.tokenFor(ctx, q, id, tok); err != nil {
		return Application{}, err
	}
	r, err := s.byID(ctx, q, id)
	if err != nil {
		return Application{}, err
	}
	return applicationOf(&r), nil
}

// Verify follows the verification link: unverified becomes submitted,
// within the link's lifetime by the database clock. On a submitted (or
// later) application it answers the state unchanged.
func (s *Service) Verify(ctx context.Context, id, tok string) (Application, error) {
	if err := s.needApplications(); err != nil {
		return Application{}, err
	}
	var out Application
	verified := false
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := s.tokenFor(ctx, q, id, tok); err != nil {
			return err
		}
		r, err := q.VerifyApplication(ctx, id)
		if store.IsNoRows(err) {
			cur, err := s.byID(ctx, q, id)
			if err != nil {
				return err
			}
			if cur.State == StateUnverified {
				s.count(CounterLinkExpired)
				return httpx.Refuse(http.StatusConflict, SlugLinkExpired, "the verification link expired; apply again")
			}
			out = applicationOf(&cur)
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.record(ctx, q, audit.Event{Actor: applicantActor(), EntityType: applicationTableName, EntityID: id,
			EventType: audit.EventRegistryApplicationVerified, Payload: map[string]any{"state": r.State}}); err != nil {
			return err
		}
		out, verified = applicationOf(&r), true
		return nil
	})
	if err != nil {
		return Application{}, err
	}
	if verified {
		s.count(CounterVerified)
	}
	return out, nil
}

// Page selects applications after a cursor.
type Page struct {
	State   string
	AfterAt time.Time
	AfterID string
	Limit   int
}

// List reads one page, oldest submitted first, without content.
func (s *Service) List(ctx context.Context, p Page) ([]Application, error) {
	if err := s.needApplications(); err != nil {
		return nil, err
	}
	var st *string
	if p.State != "" {
		st = &p.State
	}
	rows, err := s.DB.Queries().ListApplications(ctx, gen.ListApplicationsParams{State: st, AfterAt: p.AfterAt, AfterID: p.AfterID, PageSize: int32(p.Limit)})
	if err != nil {
		return nil, err
	}
	out := make([]Application, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		out = append(out, Application{
			ID: r.ID, State: r.State, OperatorType: r.OperatorType, Lang: r.Lang, SubmittedAt: r.SubmittedAt, VerifiedAt: r.VerifiedAt,
			RegistrarID: deref(r.RegistrarID), ReviewStartedAt: r.ReviewStartedAt, DecidedAt: r.DecidedAt,
			RefusalReason: deref(r.RefusalReason), IssuedNumber: deref(r.IssuedNumber), OperatorID: deref(r.OperatorID), ValidUntil: r.ValidUntil,
		})
	}
	return out, nil
}

// PersonalData opens an application's content for a registrar, with a
// purpose: the registry_application_pii_viewed row is written in the
// transaction that reads the row, before anything is opened.
func (s *Service) PersonalData(ctx context.Context, id, purpose string, actor audit.Actor) (Applicant, error) {
	if err := s.needApplications(); err != nil {
		return Applicant{}, err
	}
	if strings.TrimSpace(purpose) == "" || utf8.RuneCountInString(purpose) > 200 {
		return Applicant{}, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "a personal-data read needs a purpose",
			core.Fieldf("purpose", "required: say why the application is read (at most 200 characters)"))
	}
	var out Applicant
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		r, err := s.byID(ctx, q, id)
		if err != nil {
			return err
		}
		if err := s.record(ctx, q, audit.Event{Actor: actor, Purpose: purpose, EntityType: applicationTableName, EntityID: id,
			EventType: audit.EventRegistryApplicationPIIViewed, Payload: map[string]any{"state": r.State}}); err != nil {
			return err
		}
		return s.open(r.PiiKeyID, payloadAAD(id), r.PayloadEnc, &out)
	})
	return out, err
}

func conflictState(state string, want ...string) error {
	return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "the application is "+state,
		core.Fieldf("state", "is %s; this step needs %s", state, strings.Join(want, " or ")))
}

// StartReview takes a submitted application for review.
func (s *Service) StartReview(ctx context.Context, id string, actor audit.Actor) (Application, error) {
	if err := s.needApplications(); err != nil {
		return Application{}, err
	}
	var out Application
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		cur, err := q.ApplicationForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFoundApplication()
		}
		if err != nil {
			return err
		}
		if cur.State != StateSubmitted {
			return conflictState(cur.State, StateSubmitted)
		}
		r, err := q.StartApplicationReview(ctx, gen.StartApplicationReviewParams{ID: id, RegistrarID: &actor.ID})
		if err != nil {
			return err
		}
		if err := s.record(ctx, q, audit.Event{Actor: actor, EntityType: applicationTableName, EntityID: id,
			EventType: audit.EventRegistryApplicationReview, Payload: map[string]any{}}); err != nil {
			return err
		}
		out = applicationOf(&r)
		return nil
	})
	return out, err
}

// Approve registers the applicant: the number and its secret part are
// chosen once and kept on the application (the secret sealed) in their
// own transaction; then, in one transaction holding the application's
// row lock throughout, the state is checked again, the operator is
// registered through the registry (source portal, source_ref the
// application id, so a retried approval finds it instead of registering
// it twice), the application approved, the secret moved into the
// approval e-mail's outbox row and the events row written. A refusal
// taking the same lock waits for the approval and then finds it decided,
// so no operator is registered for a refused application. The secret
// part is in no response.
func (s *Service) Approve(ctx context.Context, id string, validUntil *time.Time, actor audit.Actor) (Application, error) {
	if err := s.needApplications(); err != nil {
		return Application{}, err
	}
	app, applicant, secret, err := s.chooseNumber(ctx, id, validUntil)
	if err != nil {
		return Application{}, err
	}
	var out Application
	taken := false
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		cur, err := q.ApplicationForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFoundApplication()
		}
		if err != nil {
			return err
		}
		if cur.State == StateApproved {
			out = applicationOf(&cur)
			return nil
		}
		if cur.State != StateUnderReview {
			return conflictState(cur.State, StateUnderReview)
		}
		if deref(cur.IssuedNumber) != app.IssuedNumber {
			return httpx.Refuse(http.StatusConflict, httpx.SlugConflict,
				"the number chosen for this application changed meanwhile; approve again")
		}
		op, collided, err := s.registerOperator(ctx, &app, &applicant, secret, actor)
		if err != nil {
			return err
		}
		if collided {
			taken = true
			return q.ClearApplicationIssuedNumber(ctx, id)
		}
		r, err := q.ApproveApplication(ctx, gen.ApproveApplicationParams{ID: id, OperatorID: &op.ID, RegistrarID: &actor.ID})
		if err != nil {
			return err
		}
		tok, err := s.applicationToken(id, s.statusLinkExpiry(*r.DecidedAt))
		if err != nil {
			return err
		}
		if err := s.queueMail(ctx, q, MailApproved, r.Lang, id, Message{To: applicant.PII.ContactEmail, Vars: map[string]string{
			"number": op.RegistrationNumber, "secret": secret, "valid_until": stamp(op.ValidUntil), "link": s.link("/applications/"+id, tok),
		}}); err != nil {
			return err
		}
		if err := s.record(ctx, q, audit.Event{Actor: actor, EntityType: applicationTableName, EntityID: id,
			EventType: audit.EventRegistryApplicationApproved, Payload: map[string]any{
				"operator_id": op.ID, "registration_number": op.RegistrationNumber, "valid_until": op.ValidUntil.UTC(),
			}}); err != nil {
			return err
		}
		out = applicationOf(&r)
		return nil
	})
	if err != nil {
		return Application{}, err
	}
	if taken {
		return Application{}, httpx.Refuse(http.StatusConflict, httpx.SlugConflict,
			"the number chosen for this application was registered meanwhile; approve again to choose another")
	}
	s.count(CounterApproved)
	return out, nil
}

// chooseNumber reads the application under review with its content and
// returns the number and secret part chosen for it, choosing and keeping
// them on the first approval.
func (s *Service) chooseNumber(ctx context.Context, id string, validUntil *time.Time) (Application, Applicant, string, error) {
	var app Application
	var applicant Applicant
	var secret string
	// One connection: the number is checked through the registry reader
	// on the transaction that holds the row lock, never on a second one.
	err := s.Registry.Read(ctx, func(q *gen.Queries, reg registry.Reader) error {
		cur, err := q.ApplicationForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFoundApplication()
		}
		if err != nil {
			return err
		}
		if cur.State != StateUnderReview {
			return conflictState(cur.State, StateUnderReview)
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if validUntil != nil && !validUntil.After(now) {
			return core.Fieldf("valid_until", "must be in the future")
		}
		if err := s.open(cur.PiiKeyID, payloadAAD(id), cur.PayloadEnc, &applicant); err != nil {
			return err
		}
		if cur.IssuedNumber != nil {
			// A retried approval approves what the first one chose: another
			// valid_until is a different decision, not a retry.
			if validUntil != nil && cur.ValidUntil != nil && !validUntil.Truncate(time.Microsecond).Equal(*cur.ValidUntil) {
				return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "an approval of this application with another validity is in progress",
					core.Fieldf("valid_until", "is %s for the approval in progress; retry with it, or refuse the application", cur.ValidUntil.UTC().Format(time.RFC3339Nano)))
			}
			if err := s.open(cur.PiiKeyID, secretAAD(id), cur.SecretEnc, &secret); err != nil {
				return err
			}
			app = applicationOf(&cur)
			return nil
		}
		number, err := IssueNumber(ctx, reg, s.Config.IssuePrefix, s.Config.IssueRandomLen, func() { s.count(CounterIssueCollision) })
		if err != nil {
			return err
		}
		if secret, err = SecretPart(); err != nil {
			return err
		}
		sealed, err := s.seal(secretAAD(id), secret)
		if err != nil {
			return err
		}
		until := now.UTC().Add(s.Config.Validity)
		if validUntil != nil {
			until = validUntil.UTC()
		}
		r, err := q.SetApplicationIssuedNumber(ctx, gen.SetApplicationIssuedNumberParams{ID: id, IssuedNumber: &number, SecretEnc: sealed, ValidUntil: &until})
		if err != nil {
			return err
		}
		app = applicationOf(&r)
		return nil
	})
	return app, applicant, secret, err
}

// registerOperator registers the operator of an application through the
// registry, once: a retried approval finds the operator the first one
// registered (source portal, source_ref the application id). collided
// is a number another registration took meanwhile: the caller clears it
// on the application, under its row lock, and the next approval chooses
// another.
func (s *Service) registerOperator(ctx context.Context, app *Application, a *Applicant, secret string, actor audit.Actor) (op registry.Operator, collided bool, err error) {
	if op, found, err := s.Registry.OperatorBySource(ctx, registry.SourcePortal, app.ID); err != nil || found {
		return op, false, err
	}
	op, err = s.Registry.CreateOperator(ctx, registry.NewOperator{
		OperatorType: a.OperatorType, RegistrationNumber: app.IssuedNumber, SecretPart: secret, PII: a.PII,
		CompetencyConfirmation: a.CompetencyConfirmation, Authorisations: a.Authorisations, ValidUntil: *app.ValidUntil,
		Source: registry.SourcePortal, SourceRef: app.ID,
	}, actor)
	if err == nil {
		return op, false, nil
	}
	found, ok, ferr := s.Registry.OperatorBySource(ctx, registry.SourcePortal, app.ID)
	switch {
	case ferr != nil:
		return registry.Operator{}, false, ferr
	case ok:
		return found, false, nil
	case httpx.ProblemFromError(err).Status == http.StatusConflict:
		s.count(CounterIssueCollision)
		return registry.Operator{}, true, nil
	}
	return registry.Operator{}, false, err
}

// Refuse refuses a submitted or reviewed application with a reason,
// mailed to the applicant.
func (s *Service) Refuse(ctx context.Context, id, reason string, actor audit.Actor) (Application, error) {
	if err := s.needApplications(); err != nil {
		return Application{}, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || utf8.RuneCountInString(reason) > maxReasonRunes || !utf8.ValidString(reason) {
		return Application{}, core.Fieldf("reason", "required, at most %d characters", maxReasonRunes)
	}
	var out Application
	err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		cur, err := q.ApplicationForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFoundApplication()
		}
		if err != nil {
			return err
		}
		if cur.State != StateSubmitted && cur.State != StateUnderReview {
			return conflictState(cur.State, StateSubmitted, StateUnderReview)
		}
		// An approval that registered the operator and failed before its
		// decision is finished by approving again, never refused: the
		// registry would keep an operator for a refused application.
		if cur.IssuedNumber != nil {
			_, found, err := s.Registry.OperatorBySource(ctx, registry.SourcePortal, id)
			if err != nil {
				return err
			}
			if found {
				return httpx.Refuse(http.StatusConflict, httpx.SlugConflict,
					"an operator is registered for this application already; approve it again to finish the approval",
					core.Fieldf("state", "an approval is half-finished: approve again"))
			}
		}
		var a Applicant
		if err := s.open(cur.PiiKeyID, payloadAAD(id), cur.PayloadEnc, &a); err != nil {
			return err
		}
		r, err := q.RefuseApplication(ctx, gen.RefuseApplicationParams{ID: id, RefusalReason: &reason, RegistrarID: &actor.ID})
		if err != nil {
			return err
		}
		tok, err := s.applicationToken(id, s.statusLinkExpiry(*r.DecidedAt))
		if err != nil {
			return err
		}
		if err := s.queueMail(ctx, q, MailRefused, r.Lang, id, Message{To: a.PII.ContactEmail, Vars: map[string]string{
			"reason": reason, "link": s.link("/applications/"+id, tok),
		}}); err != nil {
			return err
		}
		if err := s.record(ctx, q, audit.Event{Actor: actor, EntityType: applicationTableName, EntityID: id,
			EventType: audit.EventRegistryApplicationRefused, Payload: map[string]any{"reason": reason}}); err != nil {
			return err
		}
		out = applicationOf(&r)
		return nil
	})
	if err != nil {
		return Application{}, err
	}
	s.count(CounterRefused)
	return out, nil
}
