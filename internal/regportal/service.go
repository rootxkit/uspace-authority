package regportal

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/occurrences"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Counters of the portal (status line and /metrics, E-09).
const (
	CounterOff              = "registry_portal_off"                  // a portal operation asked for with its flag off (404)
	CounterBudgetSpent      = "registry_portal_budget_spent"         // a request refused 429 by a database budget
	CounterCheckLimited     = "registry_check_rate_limited"          // a public check refused 429 by the per-address limiter
	CounterSubmitted        = "registry_applications_submitted"      // applications received (unverified)
	CounterVerified         = "registry_applications_verified"       // applications submitted by their link
	CounterLinkExpired      = "registry_applications_link_expired"   // a verification link followed after it expired
	CounterTokenRefused     = "registry_portal_token_refused"        // a link token that did not verify
	CounterApproved         = "registry_applications_approved"       // applications approved (an operator registered)
	CounterRefused          = "registry_applications_refused"        // applications refused by a registrar
	CounterIssueCollision   = "registry_issue_number_taken"          // an issued number found registered already; another drawn
	CounterPurged           = "registry_applications_purged"         // applications deleted past their retention
	CounterMailSent         = "registry_portal_mail_sent"            // portal e-mails delivered
	CounterMailRetried      = "registry_portal_mail_retried"         // a delivery that failed and waits for its retry
	CounterMailFailed       = "registry_portal_mail_failed"          // a message given up (attempts spent or a permanent refusal)
	CounterLinksMailed      = "registry_operator_links_mailed"       // operator links queued for delivery
	CounterLinksUnmailed    = "registry_operator_links_not_mailed"   // a link request for a number not in good standing, or past the operator's budget: answered 202, nothing mailed
	CounterLinkSpent        = "registry_operator_link_spent_refused" // an operator link used again or after its expiry (401)
	CounterOperatorReported = "registry_operator_reports"            // operators' occurrence reports taken through a link
)

// Problem slugs of the portal.
const (
	SlugBudget          = "rate_limited"
	SlugLinkExpired     = "link_expired"
	SlugLinkSpent       = "link_spent"
	SlugIssuance        = "issuance_pattern_mismatch"
	SlugPortalOff       = httpx.SlugNotFound
	SlugMailUnavailable = "mail_unavailable"
)

// Budget buckets (registry_portal_hits.bucket).
const (
	BucketApplication    = "application"
	BucketLinkIP         = "operator_link_ip"
	BucketLinkOperator   = "operator_link_operator"
	maxIssueAttempts     = 8
	issueAlphabet        = "0123456789abcdefghijklmnopqrstuvwxyz"
	secretPartLen        = 3
	applicantActorID     = "registry_portal"
	applicationTableName = "registry_applications"
)

// Registry is what the portal needs of internal/registry.
type Registry interface {
	CheckNumber(ctx context.Context, number string) (registry.PublicCheck, error)
	NumberFree(ctx context.Context, number string) (public string, free bool, err error)
	CreateOperator(ctx context.Context, in registry.NewOperator, actor audit.Actor) (registry.Operator, error)
	OperatorBySource(ctx context.Context, source, ref string) (registry.Operator, bool, error)
	ContactForLink(ctx context.Context, number string) (registry.OperatorContact, bool, error)
	// Read runs fn in one relational transaction with a registry reader
	// over it: what the portal asks of the registry while it holds an
	// application's row lock is asked on that same connection.
	Read(ctx context.Context, fn func(q *gen.Queries, r registry.Reader) error) error
}

// NumberChecker answers whether a registration number is free (the
// registry, or its reader inside a transaction).
type NumberChecker interface {
	NumberFree(ctx context.Context, number string) (public string, free bool, err error)
}

// Occurrences is WP-18's intake as the operator path uses it.
type Occurrences interface {
	Intake(ctx context.Context, o occurrences.Origin, in occurrences.Input) (occurrences.Receipt, error)
}

// Config is the portal's configuration (internal/config RegistryPortal).
type Config struct {
	Applications    bool
	OperatorReports bool
	PortalURL       string
	VerifyTTL       time.Duration
	Retain          time.Duration
	Validity        time.Duration
	ApplicationsIP  int
	Window          time.Duration
	IssuePrefix     string
	IssueRandomLen  int
	LinkTTL         time.Duration
	LinksIP         int
	LinksOperator   int
	MailBatch       int
	MailMaxAttempts int
	MailRetry       time.Duration
	MailTimeout     time.Duration
}

// Service is the public check, the applications, the operator links and
// the portal's mail outbox (api only).
type Service struct {
	DB          *pg.DB
	Audit       *audit.Writer
	Registry    Registry
	Occurrences Occurrences
	// PublicPart cuts a registration number to its public part (regnum
	// under the active policy), for the occurrence intake.
	PublicPart occurrences.PublicPartFunc
	Signer     *Signer
	Sealer     *pii.Sealer
	Mailer     Mailer
	Catalogue  Catalogue
	Config     Config
	Counters   *core.Counters
	Logger     *slog.Logger
	Limiter    *logging.Limiter
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

func (s *Service) limited(key string) *slog.Logger {
	if s.Limiter != nil {
		return s.Limiter.Limited(key)
	}
	return s.logger()
}

func applicantActor() audit.Actor { return audit.SystemActor(applicantActorID) }

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// off is the answer of an operation whose flag is off: 404, as if the
// operation did not exist (E-01: its twin is the flag on).
func (s *Service) off(what string) error {
	s.count(CounterOff)
	return httpx.Refuse(http.StatusNotFound, SlugPortalOff, what+" is not offered by this registry (its flag is off)")
}

func (s *Service) needApplications() error {
	if !s.Config.Applications {
		return s.off("registration through the portal")
	}
	return nil
}

func (s *Service) needOperatorReports() error {
	if !s.Config.OperatorReports {
		return s.off("an operator's occurrence report through a link")
	}
	return nil
}

// BudgetSpentError is a database budget spent: 429 with Retry-After.
type BudgetSpentError struct {
	Bucket     string
	RetryAfter time.Duration
}

func (e *BudgetSpentError) Error() string {
	return fmt.Sprintf("the %s budget of this client is spent; retry after %s", e.Bucket, e.RetryAfter)
}

// spend counts one request against bucket for keyHash within window, on
// the database clock under a transaction-scoped advisory lock (so two
// replicas never both admit the last one), or refuses it with the time
// until the oldest counted request leaves the window. It runs inside
// the transaction of the act it admits.
func spend(ctx context.Context, q *gen.Queries, bucket, keyHash string, limit int, window time.Duration) error {
	if err := q.AdvisoryXactLock(ctx, pg.LockKey("regportal_budget:"+bucket+":"+keyHash)); err != nil {
		return err
	}
	used, err := q.PortalHits(ctx, gen.PortalHitsParams{Bucket: bucket, KeyHash: keyHash, WindowS: window.Seconds()})
	if err != nil {
		return err
	}
	if used.N >= int64(limit) {
		return &BudgetSpentError{Bucket: bucket, RetryAfter: time.Duration(math.Max(1, math.Ceil(used.FreesInS))) * time.Second}
	}
	return q.InsertPortalHit(ctx, gen.InsertPortalHitParams{Bucket: bucket, KeyHash: keyHash})
}

// draw is n random characters of issueAlphabet.
func draw(n int) (string, error) {
	out := make([]byte, n)
	limit := big.NewInt(int64(len(issueAlphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		out[i] = issueAlphabet[v.Int64()]
	}
	return string(out), nil
}

// IssueNumber draws a registration number the policy accepts and no
// registration holds (plan Q-A10, pending GCAA): prefix, then randomLen
// random lower-case letters and digits (the EU AMC shape by default;
// its checksum character is unverified and not computed), checked by
// the registry (regnum under the active pattern, G-07; unique on its
// compare key, G-04). A number the pattern refuses is refused at once
// (the configuration and the policy disagree: a retry cannot help); a
// number held already is drawn again, at most a few times.
func IssueNumber(ctx context.Context, reg NumberChecker, prefix string, randomLen int, taken func()) (string, error) {
	for range maxIssueAttempts {
		tail, err := draw(randomLen)
		if err != nil {
			return "", err
		}
		public, free, err := reg.NumberFree(ctx, prefix+tail)
		if err != nil {
			var fe *core.FieldError
			if errors.As(err, &fe) {
				return "", httpx.Refuse(http.StatusConflict, SlugIssuance,
					"the number the portal issues does not match the policy's registration_number_pattern: align REGISTRY_ISSUE_PREFIX and REGISTRY_ISSUE_RANDOM_LEN with the policy",
					core.Fieldf("registration_number", "%s", fe.Reason))
			}
			return "", err
		}
		if free {
			return public, nil
		}
		if taken != nil {
			taken()
		}
	}
	return "", errors.New("no free registration number after several draws")
}

// SecretPart draws the three-character EU secret part.
func SecretPart() (string, error) { return draw(secretPartLen) }

func (s *Service) seal(aadParts string, v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return s.Sealer.Seal(b, []byte(aadParts))
}

func (s *Service) open(keyID, aadParts string, sealed []byte, v any) error {
	b, err := s.Sealer.Open(keyID, sealed, []byte(aadParts))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func mailAAD(kind, applicationID string) string {
	return "registry_portal_mail:" + kind + ":" + applicationID
}

// queueMail writes one outbox row in q's transaction: sent after the
// commit by the sender job, never before.
func (s *Service) queueMail(ctx context.Context, q *gen.Queries, kind, lang, applicationID string, m Message) error {
	sealed, err := s.seal(mailAAD(kind, applicationID), m)
	if err != nil {
		return err
	}
	var app *string
	if applicationID != "" {
		app = &applicationID
	}
	_, err = q.InsertPortalMail(ctx, gen.InsertPortalMailParams{Kind: kind, ApplicationID: app, Lang: lang, PiiKeyID: s.Sealer.KeyID(), MessageEnc: sealed})
	return err
}

func (s *Service) record(ctx context.Context, q *gen.Queries, ev audit.Event) error {
	_, err := s.Audit.Record(ctx, q, ev)
	return err
}

// stamp is how an instant is written in an e-mail.
func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }
