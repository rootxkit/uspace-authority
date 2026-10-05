package certs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/cisp"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/store"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Counters (E-09: every refusal, drop and degraded state is named).
const (
	CounterIssued             = "certificates_issued"
	CounterIssueRefused       = "certificates_issue_refused"
	CounterUpdated            = "certificates_updated"
	CounterTransitions        = "certificate_transitions"
	CounterTransitionsRefused = "certificate_transitions_refused"
	CounterNotices            = "certificate_notices_recorded"
	CounterNoticesReplayed    = "certificate_notices_replayed"
	CounterNoticesRefused     = "certificate_notices_refused"
	CounterNoticesWrongClient = "certificate_notices_wrong_client"
	CounterLapsedUnused       = "certificates_lapsed_unused"
	CounterLapsedCeased       = "certificates_lapsed_ceased"
	CounterLapseRuns          = "certificate_lapse_runs"
	CounterLapseSkipped       = "certificate_lapse_skipped_locked"
	CounterLapseFailed        = "certificate_lapse_failed"
	CounterListQueued         = "ussp_list_queued"
	CounterListPending        = "ussp_list_pending"
	CounterListRepaired       = "ussp_list_repaired"
	CounterListRepairFailed   = "ussp_list_repair_failed"
	CounterKVPublished        = "certificates_kv_published"
	CounterKVFailed           = "certificates_kv_publish_failed"
	CounterKVAhead            = "certificates_kv_bucket_ahead"
	CounterRegisterServed     = "certificate_register_served"
	CounterRegisterLimited    = "certificate_register_rate_limited"
)

// Problem slugs.
const (
	SlugCodeTaken       = "certificate_code_taken"
	SlugPolicyUnknown   = "policy_unavailable"
	SlugWrongClient     = "certificate_not_yours"
	SlugNoticeReference = "notice_reference_reused"
)

// Bounds (E-10).
const (
	MaxListRows    = 500
	MaxRegisterRow = 1000
	MaxNoticesRead = 100
)

// lockCertificates serialises every certificate write, so the USSP list
// a transition queues is built after the one before it committed.
var lockCertificates = pgstore.LockKey("certificates")

// lockLapse is the lapse job's: one replica runs it at a time.
var lockLapse = pgstore.LockKey("certificates_lapse")

// ListOutbox is WP-6's outbox as the certificates use it
// (*cisp.Outbox): the CISP's checks and the signature, then the sender's
// wake-up after the commit.
type ListOutbox interface {
	Prepare(ds cisp.Dataset, payload []byte) (cisp.Prepared, error)
	Wake()
}

// Service is the certificates' logic on the relational database.
type Service struct {
	DB    *pgstore.DB
	Audit *audit.Writer
	// Clients prepares the holder's client (tokens.Registry.Prepare).
	Clients *tokens.Registry
	// Outbox nil leaves every list pending, said in the answer.
	Outbox ListOutbox
	// KV opens the certificates bucket; nil publishes nothing.
	KV        func(ctx context.Context) (jetstream.KeyValue, error)
	KVTimeout time.Duration
	// Policy is the active policy (the lapse periods copied at issue).
	Policy func() (policy.Policy, bool)
	// Issuer is this issuer: notices are taken from its tokens only.
	Issuer string
	// Audiences are the hosts a certificate's client may name for its
	// national scopes: this system's, the CISP's and the ANSP's
	// (ClientAudiences).
	Audiences []string
	// TokenTTL is the token service's TTL: how long a token issued
	// before a suspension stays valid.
	TokenTTL time.Duration
	Counters *core.Counters
	Logger   *slog.Logger
	Limiter  *logging.Limiter
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return logging.Discard()
}

func (s *Service) inc(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) warn(key, msg string, attrs ...any) {
	if s.Limiter != nil {
		s.Limiter.Limited(key).Warn(msg, attrs...)
		return
	}
	s.logger().Warn(msg, attrs...)
}

func notFound(id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such certificate",
		core.Fieldf("id", "%s is not a certificate", id))
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func factsOf(r *pggen.Certificate) Facts {
	f := Facts{Operations: r.Operations, Limited: r.Limited, Suspended: r.Suspended}
	if r.Ended != nil {
		f.Ended = *r.Ended
	}
	return f
}

// listed is whether r is on the USSP list at now.
func listed(r *pggen.Certificate, now time.Time) bool {
	return r.Holder == HolderUSSP && factsOf(r).Listed() && !r.IssuedAt.After(now) && r.ValidUntil.After(now)
}

// Publication is what became of the USSP list after a change.
type Publication struct {
	// State is queued, not_needed or pending.
	State         string
	Reason        string
	PublicationID int64
	queued        bool
}

// Publication states.
const (
	PubQueued    = "queued"
	PubNotNeeded = "not_needed"
	PubPending   = "pending"
)

// IssueInput is a certificate to issue.
type IssueInput struct {
	Holder, HolderName, HolderAddress, HolderEmail, HolderPhone, HolderURL string
	Code, BaseURL, Conditions, TermsURL                                    string
	Services, Limitations                                                  []string
	ValidFrom                                                              *time.Time
	ValidUntil                                                             time.Time
	AuthMethod                                                             string
	JWKS                                                                   json.RawMessage
}

// Issued is an issued certificate, its client and the client's secret
// (shown once).
type Issued struct {
	Certificate pggen.Certificate
	Client      tokens.ClientRecord
	Secret      string
}

func checkContact(holderName, address, email, phone, url string) []error {
	var errs []error
	if strings.TrimSpace(holderName) == "" || len(holderName) > MaxHolderName {
		errs = append(errs, core.Fieldf("holder_name", "1 to %d characters", MaxHolderName))
	}
	if len(address) > MaxAddress {
		errs = append(errs, core.Fieldf("holder_address", "longer than %d characters", MaxAddress))
	}
	if email != "" && (len(email) < 3 || len(email) > MaxEmail || !strings.Contains(email, "@")) {
		errs = append(errs, core.Fieldf("holder_email", "an e-mail address of 3 to %d characters", MaxEmail))
	}
	if len(phone) > MaxPhone {
		errs = append(errs, core.Fieldf("holder_phone", "longer than %d characters", MaxPhone))
	}
	if url != "" {
		if err := CheckHTTPSURL("holder_url", url); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

func (in *IssueInput) check() error {
	var errs []error
	if in.Holder != HolderUSSP && in.Holder != HolderCISP {
		errs = append(errs, core.Fieldf("holder", "ussp or cisp"))
	}
	errs = append(errs, checkContact(in.HolderName, in.HolderAddress, in.HolderEmail, in.HolderPhone, in.HolderURL)...)
	if err := CheckCode(in.Code); err != nil {
		errs = append(errs, err)
	}
	if svc, err := CheckServices(in.Holder, in.Services); err != nil {
		errs = append(errs, err)
	} else {
		in.Services = svc
	}
	if len(in.Conditions) > MaxConditions {
		errs = append(errs, core.Fieldf("conditions", "longer than %d characters", MaxConditions))
	}
	if err := CheckLimitations("limitations", in.Limitations); err != nil {
		errs = append(errs, err)
	}
	if in.Holder == HolderUSSP || in.BaseURL != "" {
		if in.BaseURL == "" {
			errs = append(errs, core.Fieldf("base_url", "required of a USSP"))
		} else if err := CheckHTTPSURL("base_url", in.BaseURL); err != nil {
			errs = append(errs, err)
		}
	}
	if in.Holder == HolderUSSP || in.TermsURL != "" {
		if in.TermsURL == "" {
			errs = append(errs, core.Fieldf("terms_url", "required of a USSP (Art. 5(3))"))
		} else if err := CheckHTTPSURL("terms_url", in.TermsURL); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Issue issues a certificate and registers its client in one
// transaction (06 §3: least privilege, ScopesFor).
func (s *Service) Issue(ctx context.Context, in IssueInput, actor audit.Actor) (Issued, error) {
	if err := in.check(); err != nil {
		s.inc(CounterIssueRefused)
		return Issued{}, err
	}
	p, ok := s.Policy()
	if !ok {
		s.inc(CounterIssueRefused)
		return Issued{}, httpx.Refuse(http.StatusServiceUnavailable, SlugPolicyUnknown,
			"the active policy is not read yet: the Art. 16(2) lapse periods are unknown; nothing was issued")
	}
	id, err := newID()
	if err != nil {
		return Issued{}, err
	}
	clientID := ClientIDFor(in.Holder, in.Code)
	client, secret, err := s.Clients.Prepare(tokens.ClientInput{
		ID: clientID, Scopes: ScopesFor(in.Holder, in.Services), Audiences: slices.Clone(s.Audiences),
		AuthMethod: in.AuthMethod, JWKS: in.JWKS, CertificateID: id, Note: "certificate " + id + " (" + in.Code + ")",
	}, actor)
	if err != nil {
		s.inc(CounterIssueRefused)
		return Issued{}, err
	}
	var out Issued
	err = s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		taken, err := q.CertificateCodeTaken(ctx, in.Code)
		if err != nil {
			return err
		}
		if taken {
			return httpx.Refuse(http.StatusConflict, SlugCodeTaken, "the code is another certificate's (codes are never reused)",
				core.Fieldf("code", "%s is taken", in.Code))
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		issued := now
		if in.ValidFrom != nil {
			issued = *in.ValidFrom
		}
		if !in.ValidUntil.After(issued) {
			return core.Fieldf("valid_until", "must be after the issue (%s)", issued.UTC().Format(time.RFC3339))
		}
		limits := in.Limitations
		if limits == nil {
			limits = []string{}
		}
		row, err := q.InsertCertificate(ctx, pggen.InsertCertificateParams{
			ID: id, Holder: in.Holder, HolderName: strings.TrimSpace(in.HolderName), HolderAddress: in.HolderAddress,
			HolderEmail: in.HolderEmail, HolderPhone: in.HolderPhone, HolderUrl: in.HolderURL, Code: in.Code, ClientID: clientID,
			BaseUrl: in.BaseURL, Services: in.Services, Conditions: in.Conditions, Limitations: limits, TermsUrl: in.TermsURL,
			IssuedAt: issued, ValidUntil: in.ValidUntil, CreatedBy: actor.ID,
			LapseUnusedAfterMonths: int32(p.CertificateLapseUnusedMonths), LapseCeasedAfterMonths: int32(p.CertificateLapseCeasedMonths),
		})
		if err != nil {
			return err
		}
		c, err := tokens.InsertPrepared(ctx, tokens.PGTx(q, s.Audit), client, actor)
		if err != nil {
			return err
		}
		out = Issued{Certificate: row, Client: c, Secret: secret}
		_, err = s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: "certificate", EntityID: id, EventType: audit.EventCertificateIssued,
			Payload: map[string]any{
				"holder": in.Holder, "holder_name": row.HolderName, "code": in.Code, "client_id": clientID,
				"services": in.Services, "scopes": c.Scopes, "issued_at": row.IssuedAt, "valid_until": row.ValidUntil,
				"lapse_unused_after_months": row.LapseUnusedAfterMonths, "lapse_ceased_after_months": row.LapseCeasedAfterMonths,
				"policy_version": p.Version,
			},
		})
		return err
	})
	if err != nil {
		s.inc(CounterIssueRefused)
		return Issued{}, err
	}
	s.inc(CounterIssued)
	s.afterCommit(ctx, Publication{State: PubNotNeeded})
	return out, nil
}

// Change is a certificate after a change, its client's status and what
// became of the USSP list.
type Change struct {
	Certificate pggen.Certificate
	// ClientStatus is the client's status when the change moved it.
	ClientStatus string
	// TokensValidUntil is set when the client was suspended or revoked.
	TokensValidUntil *time.Time
	List             Publication
}

// Transition applies an authority action (ActionSuspend, ActionLimit,
// ActionRevoke, ActionReinstate) with its reason; limit takes the
// limitations, which replace the ones held.
func (s *Service) Transition(ctx context.Context, id, action, reason string, limitations []string, actor audit.Actor) (Change, error) {
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > MaxReason {
		return Change{}, core.Fieldf("reason", "1 to %d characters", MaxReason)
	}
	if action == ActionLimit {
		if len(limitations) == 0 {
			return Change{}, core.Fieldf("limitations", "at least one limitation")
		}
		if err := CheckLimitations("limitations", limitations); err != nil {
			return Change{}, err
		}
	}
	var out Change
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		row, err := q.CertificateForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFound(id)
		}
		if err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		before := factsOf(&row)
		after, err := Apply(before, action)
		if err != nil {
			s.inc(CounterTransitionsRefused)
			return conflict(err)
		}
		limits := row.Limitations
		switch {
		case action == ActionLimit:
			limits = slices.Clone(limitations)
		case action == ActionReinstate && before.Limited && !after.Limited:
			limits = []string{}
		}
		var ended *string
		if after.Ended != "" {
			e := after.Ended
			ended = &e
		}
		updated, err := q.SetCertificateState(ctx, pggen.SetCertificateStateParams{
			Operations: after.Operations, OperationsStartedAt: row.OperationsStartedAt, OperationsCeasedAt: row.OperationsCeasedAt,
			Limited: after.Limited, Limitations: limits, Suspended: after.Suspended, Ended: ended,
			StatusReason: reason, ChangedBy: actor.ID, ID: id,
		})
		if err != nil {
			return err
		}
		out.Certificate = updated
		clientStatus := ""
		switch {
		case after.Ended != "":
			clientStatus = tokens.StatusRevoked
		case action == ActionSuspend:
			clientStatus = tokens.StatusSuspended
		case action == ActionReinstate && before.Suspended:
			clientStatus = tokens.StatusActive
		}
		if clientStatus != "" {
			if err := s.setClient(ctx, q, row.ClientID, clientStatus, "certificate "+action+": "+reason, actor); err != nil {
				return err
			}
			out.ClientStatus = clientStatus
			if clientStatus != tokens.StatusActive {
				until := now.Add(s.TokenTTL).UTC()
				out.TokensValidUntil = &until
			}
		}
		if _, err := s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: "certificate", EntityID: id, EventType: audit.EventCertificateStatusChanged,
			Payload: map[string]any{
				"action": action, "from": row.Status, "to": updated.Status, "reason": reason,
				"limitations": updated.Limitations, "client_id": row.ClientID, "client_status": clientStatus,
			},
		}); err != nil {
			return err
		}
		out.List, err = s.listAfter(ctx, q, &row, &updated, now, actor)
		return err
	})
	if err != nil {
		return Change{}, err
	}
	s.inc(CounterTransitions)
	s.afterCommit(ctx, out.List)
	return out, nil
}

// setClient moves the certificate's client to status (06 §2 T9),
// recorded as an oauth_client_updated events row when it changed.
func (s *Service) setClient(ctx context.Context, q *pggen.Queries, clientID, status, why string, actor audit.Actor) error {
	before, err := q.SetCertificateClientStatus(ctx, pggen.SetCertificateClientStatusParams{Status: status, UpdatedBy: actor.ID, ClientID: clientID})
	if err != nil {
		return fmt.Errorf("certificate client %s: %w", clientID, err)
	}
	if before == status {
		return nil
	}
	_, err = s.Audit.Record(ctx, q, audit.Event{
		Actor: actor, EntityType: "oauth_client", EntityID: clientID, EventType: audit.EventOAuthClientUpdated,
		Payload: map[string]any{"client_id": clientID, "before": map[string]any{"status": before},
			"after": map[string]any{"status": status}, "cause": why},
	})
	return err
}

// listAfter queues the USSP list in q's transaction when the change
// moved before to after on or off it, or changed it while on it; it
// raises the wanted counter first, so a list that cannot be queued now
// is the repair job's (the durable certificate_list_state).
func (s *Service) listAfter(ctx context.Context, q *pggen.Queries, before, after *pggen.Certificate, now time.Time, actor audit.Actor) (Publication, error) {
	if !listed(before, now) && !listed(after, now) {
		return Publication{State: PubNotNeeded}, nil
	}
	return s.queueList(ctx, q, actor, false)
}

// queueList raises wanted, builds the list from q's view and queues it
// signed; a list the outbox refuses is left pending with the reason
// (strict: the error is returned instead, for publish-list). Only the
// operator's publish-list (strict) resolves a conflict at the CISP; a
// list queued by a change or the repair waits behind one (audit A-S2).
func (s *Service) queueList(ctx context.Context, q *pggen.Queries, actor audit.Actor, strict bool) (Publication, error) {
	wanted, err := q.WantUSSPList(ctx)
	if err != nil {
		return Publication{}, err
	}
	payload, digest, _, err := s.buildList(ctx, q)
	if err != nil {
		return Publication{}, err
	}
	pending := func(why error) (Publication, error) {
		if strict {
			return Publication{}, why
		}
		s.inc(CounterListPending)
		reason := httpx.ProblemFromError(why).Detail
		if reason == "" {
			reason = why.Error()
		}
		if err := q.USSPListFailed(ctx, reason); err != nil {
			return Publication{}, err
		}
		return Publication{State: PubPending, Reason: reason}, nil
	}
	if s.Outbox == nil {
		return pending(errors.New("no CISP outbox in this process"))
	}
	prepared, err := s.Outbox.Prepare(cisp.DatasetUSSPList, payload)
	if err != nil {
		return pending(err)
	}
	prepared.ResolvesConflict = strict
	row, _, err := cisp.EnqueueTx(ctx, q, s.Audit, prepared, 0, actor)
	if err != nil {
		return Publication{}, err
	}
	if err := q.USSPListEnqueued(ctx, pggen.USSPListEnqueuedParams{Wanted: wanted, ListedDigest: digest}); err != nil {
		return Publication{}, err
	}
	s.inc(CounterListQueued)
	return Publication{State: PubQueued, PublicationID: row.ID, queued: true}, nil
}

// buildList is the list as q sees it now, with the digest of the
// certificates it was built from ("" for an empty list).
func (s *Service) buildList(ctx context.Context, q *pggen.Queries) ([]byte, string, int, error) {
	rows, err := q.ListedUSSPCertificates(ctx, MaxListed+1)
	if err != nil {
		return nil, "", 0, err
	}
	now, err := q.DBNow(ctx)
	if err != nil {
		return nil, "", 0, err
	}
	payload, n, err := BuildList(rows, now)
	if err != nil {
		return nil, "", 0, err
	}
	return payload, listDigest(rows), n, nil
}

// listDigest identifies the certificates a list is built from.
func listDigest(rows []pggen.Certificate) string {
	if len(rows) == 0 {
		return ""
	}
	h := sha256.New()
	for i := range rows {
		_, _ = fmt.Fprintf(h, "%s:%d;", rows[i].ID, rows[i].RowVersion)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// afterCommit wakes the sender and republishes the register to KV:
// both only after the commit (a rolled-back change never reaches the
// bus). A failed KV write is repaired by the periodic republish.
func (s *Service) afterCommit(ctx context.Context, p Publication) {
	if p.queued && s.Outbox != nil {
		s.Outbox.Wake()
	}
	if err := s.Republish(context.WithoutCancel(ctx)); err != nil {
		s.warn("certificates_kv", "certificate register not published to KV; the periodic republish retries",
			slog.String("error", err.Error()))
	}
}

// PublishList queues the USSP list now (POST /v1/certificates/publish-list);
// the outbox's refusal is the caller's answer.
func (s *Service) PublishList(ctx context.Context, actor audit.Actor) (pub Publication, wanted int64, n int, err error) {
	err = s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		var err error
		if pub, err = s.queueList(ctx, q, actor, true); err != nil {
			return err
		}
		st, err := q.USSPListState(ctx)
		if err != nil {
			return err
		}
		wanted = st.Wanted
		rows, err := q.ListedUSSPCertificates(ctx, MaxListed+1)
		n = len(rows)
		return err
	})
	if err != nil {
		return Publication{}, 0, 0, err
	}
	s.afterCommit(ctx, pub)
	return pub, wanted, n, nil
}

// RepairList queues the list when a change wanted one that was not
// queued, or when the certificates listed now differ from those the
// queued list was built from (one passed its valid_until). It reports
// whether it queued one.
func (s *Service) RepairList(ctx context.Context) (bool, error) {
	var pub Publication
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		st, err := q.USSPListState(ctx)
		if err != nil {
			return err
		}
		rows, err := q.ListedUSSPCertificates(ctx, MaxListed+1)
		if err != nil {
			return err
		}
		if st.Wanted <= st.Enqueued && listDigest(rows) == st.ListedDigest {
			return nil
		}
		pub, err = s.queueList(ctx, q, audit.SystemActor("certificates"), false)
		return err
	})
	if err != nil {
		s.inc(CounterListRepairFailed)
		return false, err
	}
	if pub.queued {
		s.inc(CounterListRepaired)
		s.afterCommit(ctx, pub)
	}
	return pub.queued, nil
}

// Republish writes the certified USSPs to KV with the register's
// version. The version and the rows are read in one transaction that
// holds the certificates lock, so no write is in flight between them:
// every row_version taken is committed and seen, and the rows are the
// register at exactly that version, on every replica (audit A-S1). The
// lock is released before KV is written; an equal version may still
// overwrite (it carries a valid_until expiry).
func (s *Service) Republish(ctx context.Context) error {
	if s.KV == nil {
		return nil
	}
	var version int64
	var rows []pggen.Certificate
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		var err error
		if version, err = q.CertificateRegisterVersion(ctx); err != nil {
			return err
		}
		rows, err = q.ListedUSSPCertificates(ctx, certkv.MaxUSSPs+1)
		return err
	})
	if err != nil {
		s.inc(CounterKVFailed)
		return err
	}
	if len(rows) > certkv.MaxUSSPs {
		s.inc(CounterKVFailed)
		return fmt.Errorf("more than %d certified USSPs; the register is not published", certkv.MaxUSSPs)
	}
	reg := certkv.Register{Version: version, USSPs: make([]certkv.USSP, 0, len(rows))}
	for i := range rows {
		r := &rows[i]
		reg.USSPs = append(reg.USSPs, certkv.USSP{ClientID: r.ClientID, Code: r.Code, BaseURL: r.BaseUrl, Status: r.Status})
	}
	if s.KVTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.KVTimeout)
		defer cancel()
	}
	kv, err := s.KV(ctx)
	if err != nil {
		s.inc(CounterKVFailed)
		return err
	}
	stored, err := certkv.Put(ctx, kv, reg, 3)
	switch {
	case err != nil:
		s.inc(CounterKVFailed)
		return err
	case !stored:
		s.inc(CounterKVAhead)
	default:
		s.inc(CounterKVPublished)
	}
	return nil
}

// NoticeInput is an operating-status notice.
type NoticeInput struct {
	State     string
	At        time.Time
	Reference string
}

// Notice sources.
const (
	SourceMachine = "machine"
	SourceManual  = "manual"
)

// NoticeResult is a recorded notice.
type NoticeResult struct {
	Notice      pggen.CertificateNotice
	Certificate pggen.Certificate
	Replayed    bool
	List        Publication
}

// Caller is who sends a machine notice: the subject and issuer of its
// verified token.
type Caller struct {
	Subject, Issuer string
}

// RecordNotice records a notice: from the holder's own client (source
// machine, caller set) or entered by an admin (source manual, a
// reference required).
func (s *Service) RecordNotice(ctx context.Context, id string, in NoticeInput, source string, caller *Caller, actor audit.Actor) (NoticeResult, error) {
	var errs []error
	if in.State != NoticeStarted && in.State != NoticeCeased && in.State != NoticeRestarted {
		errs = append(errs, core.Fieldf("state", "started, ceased or restarted"))
	}
	if in.At.IsZero() {
		errs = append(errs, core.Fieldf("at", "required"))
	}
	if len(in.Reference) > MaxReference {
		errs = append(errs, core.Fieldf("reference", "longer than %d characters", MaxReference))
	}
	if source == SourceManual && strings.TrimSpace(in.Reference) == "" {
		errs = append(errs, core.Fieldf("reference", "the letter's reference is required of a notice entered by hand"))
	}
	if err := errors.Join(errs...); err != nil {
		s.inc(CounterNoticesRefused)
		return NoticeResult{}, err
	}
	var ref *string
	if r := strings.TrimSpace(in.Reference); r != "" {
		ref = &r
	}
	var out NoticeResult
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		row, err := q.CertificateForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFound(id)
		}
		if err != nil {
			return err
		}
		if caller != nil && (caller.Subject != row.ClientID || caller.Issuer != s.Issuer) {
			s.inc(CounterNoticesWrongClient)
			return httpx.Refuse(http.StatusForbidden, SlugWrongClient,
				"only the certificate holder's own client of this issuer records its operating status")
		}
		if ref != nil {
			prev, err := q.CertificateNoticeByReference(ctx, pggen.CertificateNoticeByReferenceParams{CertificateID: id, Reference: ref})
			switch {
			case err == nil && prev.State == in.State:
				out = NoticeResult{Notice: prev, Certificate: row, Replayed: true, List: Publication{State: PubNotNeeded}}
				return nil
			case err == nil:
				return httpx.Refuse(http.StatusConflict, SlugNoticeReference, "the reference names another notice",
					core.Fieldf("reference", "recorded already for a %s notice", prev.State))
			case !store.IsNoRows(err):
				return err
			}
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if err := CheckNoticeTime(in.At, row.IssuedAt, now); err != nil {
			return err
		}
		if err := CheckNoticeOrder(in.State, in.At, row.OperationsStartedAt, row.OperationsCeasedAt); err != nil {
			return err
		}
		after, err := Notice(factsOf(&row), in.State)
		if err != nil {
			return conflict(err)
		}
		at := in.At.UTC()
		started, ceased := row.OperationsStartedAt, row.OperationsCeasedAt
		switch in.State {
		case NoticeStarted, NoticeRestarted:
			started, ceased = &at, nil
		case NoticeCeased:
			ceased = &at
		}
		var ended *string
		reason := "notice " + in.State
		if ref != nil {
			reason += " (" + *ref + ")"
		}
		updated, err := q.SetCertificateState(ctx, pggen.SetCertificateStateParams{
			Operations: after.Operations, OperationsStartedAt: started, OperationsCeasedAt: ceased,
			Limited: after.Limited, Limitations: row.Limitations, Suspended: after.Suspended, Ended: ended,
			StatusReason: reason, ChangedBy: actor.ID, ID: id,
		})
		if err != nil {
			return err
		}
		notice, err := q.InsertCertificateNotice(ctx, pggen.InsertCertificateNoticeParams{
			CertificateID: id, State: in.State, At: at, Reference: ref, Source: source, RecordedBy: actor.ID,
		})
		if err != nil {
			return err
		}
		if _, err := s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: "certificate", EntityID: id, EventType: audit.EventCertificateNotice,
			Payload: map[string]any{"state": in.State, "at": at, "reference": ref, "source": source, "notice_id": notice.ID,
				"from": row.Status, "to": updated.Status},
		}); err != nil {
			return err
		}
		out = NoticeResult{Notice: notice, Certificate: updated}
		out.List, err = s.listAfter(ctx, q, &row, &updated, now, actor)
		return err
	})
	if err != nil {
		var p *httpx.ProblemError
		if errors.As(err, &p) || errors.As(err, new(*core.FieldError)) {
			s.inc(CounterNoticesRefused)
		}
		return NoticeResult{}, err
	}
	if out.Replayed {
		s.inc(CounterNoticesReplayed)
		return out, nil
	}
	s.inc(CounterNotices)
	s.afterCommit(ctx, out.List)
	return out, nil
}

// Patch corrects a certificate's details; nil fields stay.
type Patch struct {
	HolderName, HolderAddress, HolderEmail, HolderPhone, HolderURL *string
	BaseURL, Conditions, TermsURL                                  *string
	Limitations                                                    *[]string
	ValidUntil                                                     *time.Time
}

// Update applies p, audited with the fields before and after.
func (s *Service) Update(ctx context.Context, id string, p Patch, actor audit.Actor) (Change, error) {
	var out Change
	err := s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		row, err := q.CertificateForUpdate(ctx, id)
		if store.IsNoRows(err) {
			return notFound(id)
		}
		if err != nil {
			return err
		}
		next := pggen.UpdateCertificateDetailsParams{
			HolderName: row.HolderName, HolderAddress: row.HolderAddress, HolderEmail: row.HolderEmail, HolderPhone: row.HolderPhone,
			HolderUrl: row.HolderUrl, BaseUrl: row.BaseUrl, Conditions: row.Conditions, Limitations: row.Limitations,
			TermsUrl: row.TermsUrl, ValidUntil: row.ValidUntil, UpdatedBy: actor.ID, ID: id,
		}
		changed := map[string]any{}
		set := func(field string, dst *string, v *string) {
			if v != nil && *v != *dst {
				changed[field] = map[string]any{"before": *dst, "after": *v}
				*dst = *v
			}
		}
		set("holder_name", &next.HolderName, p.HolderName)
		set("holder_address", &next.HolderAddress, p.HolderAddress)
		set("holder_email", &next.HolderEmail, p.HolderEmail)
		set("holder_phone", &next.HolderPhone, p.HolderPhone)
		set("holder_url", &next.HolderUrl, p.HolderURL)
		set("base_url", &next.BaseUrl, p.BaseURL)
		set("conditions", &next.Conditions, p.Conditions)
		set("terms_url", &next.TermsUrl, p.TermsURL)
		if p.Limitations != nil && !slices.Equal(*p.Limitations, next.Limitations) {
			changed["limitations"] = map[string]any{"before": next.Limitations, "after": *p.Limitations}
			next.Limitations = slices.Clone(*p.Limitations)
			if next.Limitations == nil {
				next.Limitations = []string{}
			}
		}
		if p.ValidUntil != nil && !p.ValidUntil.Equal(next.ValidUntil) {
			changed["valid_until"] = map[string]any{"before": next.ValidUntil, "after": *p.ValidUntil}
			next.ValidUntil = *p.ValidUntil
		}
		errs := checkContact(next.HolderName, next.HolderAddress, next.HolderEmail, next.HolderPhone, next.HolderUrl)
		if row.Holder == HolderUSSP || next.BaseUrl != "" {
			if err := CheckHTTPSURL("base_url", next.BaseUrl); err != nil {
				errs = append(errs, err)
			}
		}
		if row.Holder == HolderUSSP || next.TermsUrl != "" {
			if err := CheckHTTPSURL("terms_url", next.TermsUrl); err != nil {
				errs = append(errs, err)
			}
		}
		if len(next.Conditions) > MaxConditions {
			errs = append(errs, core.Fieldf("conditions", "longer than %d characters", MaxConditions))
		}
		if err := CheckLimitations("limitations", next.Limitations); err != nil {
			errs = append(errs, err)
		}
		if !next.ValidUntil.After(row.IssuedAt) {
			errs = append(errs, core.Fieldf("valid_until", "must be after the issue"))
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
		if len(changed) == 0 {
			out = Change{Certificate: row, List: Publication{State: PubNotNeeded}}
			return nil
		}
		updated, err := q.UpdateCertificateDetails(ctx, next)
		if err != nil {
			return err
		}
		if _, err := s.Audit.Record(ctx, q, audit.Event{
			Actor: actor, EntityType: "certificate", EntityID: id, EventType: audit.EventCertificateUpdated,
			Payload: map[string]any{"changed": changed},
		}); err != nil {
			return err
		}
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		out = Change{Certificate: updated}
		out.List, err = s.listAfter(ctx, q, &row, &updated, now, actor)
		return err
	})
	if err != nil {
		return Change{}, err
	}
	s.inc(CounterUpdated)
	s.afterCommit(ctx, out.List)
	return out, nil
}

// Lapse rules (Art. 16(2)), named in the transition.
const (
	RuleUnused = "lapse_unused"
	RuleCeased = "lapse_ceased"
)

// Lapse lapses every certificate not used within its
// lapse_unused_after_months of issue, and every one whose operations
// ceased lapse_ceased_after_months ago (the database clock), revoking
// their clients, each a transition with the rule named. Idempotent; a
// replica finding the job running elsewhere skips (ran false).
func (s *Service) Lapse(ctx context.Context) (lapsed []pggen.Certificate, ran bool, err error) {
	system := audit.SystemActor("certificates_lapse")
	err = s.DB.WithTx(ctx, func(q *pggen.Queries) error {
		ok, err := q.TryAdvisoryXactLock(ctx, lockLapse)
		if err != nil || !ok {
			return err
		}
		ran = true
		if err := q.AdvisoryXactLock(ctx, lockCertificates); err != nil {
			return err
		}
		unused, err := q.LapseUnusedCertificates(ctx, pggen.LapseUnusedCertificatesParams{
			Reason: RuleUnused + ": not used within lapse_unused_after_months of issue (Reg. 2021/664 Art. 16(2))", ChangedBy: system.ID})
		if err != nil {
			return err
		}
		ceased, err := q.LapseCeasedCertificates(ctx, pggen.LapseCeasedCertificatesParams{
			Reason: RuleCeased + ": operations ceased for lapse_ceased_after_months (Reg. 2021/664 Art. 16(2))", ChangedBy: system.ID})
		if err != nil {
			return err
		}
		record := func(rows []pggen.Certificate, rule string, months func(*pggen.Certificate) int32) error {
			for i := range rows {
				r := &rows[i]
				f := factsOf(r)
				f.Ended = ""
				if _, err := s.Audit.Record(ctx, q, audit.Event{
					Actor: system, EntityType: "certificate", EntityID: r.ID, EventType: audit.EventCertificateStatusChanged,
					Payload: map[string]any{"action": ActionLapse, "rule": rule, "months": months(r), "from": f.Status(), "to": r.Status,
						"reason": r.StatusReason, "client_id": r.ClientID, "client_status": tokens.StatusRevoked,
						"issued_at": r.IssuedAt, "operations_ceased_at": r.OperationsCeasedAt},
				}); err != nil {
					return err
				}
				if err := s.setClient(ctx, q, r.ClientID, tokens.StatusRevoked, "certificate lapsed ("+rule+")", system); err != nil {
					return err
				}
			}
			return nil
		}
		if err := record(unused, RuleUnused, func(r *pggen.Certificate) int32 { return r.LapseUnusedAfterMonths }); err != nil {
			return err
		}
		if err := record(ceased, RuleCeased, func(r *pggen.Certificate) int32 { return r.LapseCeasedAfterMonths }); err != nil {
			return err
		}
		lapsed = slices.Concat(unused, ceased)
		for range unused {
			s.inc(CounterLapsedUnused)
		}
		for range ceased {
			s.inc(CounterLapsedCeased)
		}
		return nil
	})
	if err != nil {
		s.inc(CounterLapseFailed)
		return nil, false, err
	}
	if !ran {
		s.inc(CounterLapseSkipped)
		return nil, false, nil
	}
	s.inc(CounterLapseRuns)
	if len(lapsed) > 0 {
		s.afterCommit(ctx, Publication{State: PubNotNeeded})
	}
	return lapsed, true, nil
}

// RunJobs runs the lapse job at once and every lapseEvery, and the list
// repair and the KV republish every repairEvery, until ctx ends.
func (s *Service) RunJobs(ctx context.Context, lapseEvery, repairEvery time.Duration) {
	lapse := time.NewTicker(lapseEvery)
	defer lapse.Stop()
	repair := time.NewTicker(repairEvery)
	defer repair.Stop()
	runLapse := func() {
		lapsed, ran, err := s.Lapse(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			s.warn("certificates_lapse", "certificate lapse job failed; it runs again next period", slog.String("error", err.Error()))
		case ran:
			s.logger().Info("certificate lapse job ran", slog.Int("lapsed", len(lapsed)))
		}
	}
	runRepair := func() {
		if _, err := s.RepairList(ctx); err != nil && ctx.Err() == nil {
			s.warn("ussp_list_repair", "USSP list not repaired; it is tried again next period", slog.String("error", err.Error()))
		}
		if err := s.Republish(ctx); err != nil && ctx.Err() == nil {
			s.warn("certificates_kv", "certificate register not republished to KV", slog.String("error", err.Error()))
		}
	}
	runLapse()
	runRepair()
	for {
		select {
		case <-ctx.Done():
			return
		case <-lapse.C:
			runLapse()
		case <-repair.C:
			runRepair()
		}
	}
}

// LapsesAt is when the lapse job lapses r unless its holder starts or
// restarts: nil while it operates or once it ended.
func LapsesAt(r *pggen.Certificate) *time.Time {
	if r.Ended != nil {
		return nil
	}
	var t time.Time
	switch r.Operations {
	case OpsNotStarted:
		t = r.IssuedAt.AddDate(0, int(r.LapseUnusedAfterMonths), 0)
	case OpsCeased:
		if r.OperationsCeasedAt == nil {
			return nil
		}
		t = r.OperationsCeasedAt.AddDate(0, int(r.LapseCeasedAfterMonths), 0)
	default:
		return nil
	}
	t = t.UTC()
	return &t
}
