package regportal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/occurrences"
	"github.com/rootxkit/uspace-authority/internal/registry"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

var registrar = audit.Actor{Type: audit.ActorUser, ID: "registrar-1", Realm: audit.RealmConsole}

// sentMail is a Mailer that keeps what it sends, or fails with err.
type sentMail struct {
	mu   sync.Mutex
	msgs []mailed
	err  error
	// during runs inside each delivery, before it is kept.
	during func()
}

type mailed struct{ to, subject, body string }

func (m *sentMail) Send(_ context.Context, to, subject, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.during != nil {
		m.during()
	}
	if m.err != nil {
		return m.err
	}
	m.msgs = append(m.msgs, mailed{to, subject, body})
	return nil
}

func (m *sentMail) last(t *testing.T) mailed {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.msgs) == 0 {
		t.Fatal("nothing was mailed")
	}
	return m.msgs[len(m.msgs)-1]
}

// intake records what the occurrence intake was handed.
type intake struct {
	mu      sync.Mutex
	origins []occurrences.Origin
}

func (i *intake) Intake(_ context.Context, o occurrences.Origin, in occurrences.Input) (occurrences.Receipt, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.origins = append(i.origins, o)
	return occurrences.Receipt{Report: occurrences.Report{ID: "01JTEST0000000000000000000", ReportRef: in.ReportRef, State: "received"}}, nil
}

type itest struct {
	svc   *Service
	reg   *registry.Parts
	mail  *sentMail
	occ   *intake
	admin *sql.DB
}

func writeKey(t *testing.T, dir, name string) string {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(base64.StdEncoding.EncodeToString(k[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func newIntegration(t *testing.T) *itest {
	t.Helper()
	return newIntegrationWith(t, func(u string) string { return u })
}

// newIntegrationWith is newIntegration with the service's database URL
// passed through appURL first (the admin handle keeps the plain one).
func newIntegrationWith(t *testing.T, appURL func(string) string) *itest {
	t.Helper()
	// An approval holds its connection and the application's row lock
	// while the registry takes a second connection, and a refusal waits
	// for the lock holding one: a pool no wider than the callers of
	// TestIntegrationApproveAndRefuseRace (twelve) deadlocks it. pgx's
	// default (max(4, CPUs)) is four on the CI runner, below api's
	// PG_MAX_CONNS default of 10; the pool here is wider than the callers.
	// The pool-exhaustion risk itself is recorded in PR #45 for WP-20.
	return newIntegrationPool(t, appURL, 16)
}

// newIntegrationPool is newIntegrationWith with the relational pool
// bounded to maxConns connections (0 keeps pgxpool's default).
func newIntegrationPool(t *testing.T, appURL func(string) string, maxConns int) *itest {
	t.Helper()
	ctx := context.Background()
	pgURL := storetest.Migrated(t, migrate.Relational)
	tsURL := storetest.Migrated(t, migrate.Timeseries)
	db, err := pg.Open(ctx, store.PoolOptions{URL: appURL(pgURL), Role: pg.AppRole, ApplicationName: "uspace-authority-test", MaxConns: maxConns})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	dir := t.TempDir()
	piiKey := writeKey(t, dir, "pii.key")
	reg, err := registry.Assemble(ctx, registry.Setup{
		DB: db, Audit: audit.NewWriter(db), PIIKeyID: "pii-test", PIIKeyFile: piiKey, HashKeyFile: writeKey(t, dir, "hash.key"),
		TSURL: tsURL, TSMaxConns: 2, Pattern: func() (string, bool) { return regnum.DefaultPattern, true }, MTOMBandsG: []int{250, 900, 4000, 25000},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reg.Close)
	occ := &intake{}
	parts, err := Assemble(Setup{
		DB: db, Audit: audit.NewWriter(db), Registry: reg.Service, Occurrences: occ,
		PublicPart: occurrences.PublicPartOf(func() (string, bool) { return regnum.DefaultPattern, true }),
		PIIKeyID:   "pii-test", PIIKeyFile: piiKey, PortalKey: writeKey(t, dir, "portal.key"),
		SMTP: SMTP{Addr: "127.0.0.1:2525", From: "portal@example.test", TLS: "none"},
		Config: Config{
			Applications: true, OperatorReports: true, PortalURL: "https://portal.example.test/registry", VerifyTTL: time.Hour,
			Retain: 24 * time.Hour, Validity: 365 * 24 * time.Hour, ApplicationsIP: 3, Window: time.Hour, IssuePrefix: "GEO",
			IssueRandomLen: 12, LinkTTL: time.Hour, LinksIP: 5, LinksOperator: 2, MailBatch: 10, MailMaxAttempts: 2,
			MailRetry: time.Second, MailTimeout: 5 * time.Second,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := &sentMail{}
	parts.Service.Mailer = m
	return &itest{svc: parts.Service, reg: reg, mail: m, occ: occ, admin: storetest.Open(t, pgURL)}
}

func (it *itest) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := it.admin.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (it *itest) send(t *testing.T) Sent {
	t.Helper()
	s, err := it.svc.SendDue(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

var tokenInLink = regexp.MustCompile(`#token=(\S+)`)

func tokenOf(t *testing.T, body string) string {
	t.Helper()
	m := tokenInLink.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link in %q", body)
	}
	tok, err := url.QueryUnescape(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func applicant() Applicant {
	return Applicant{OperatorType: registry.OperatorNatural, PII: registry.OperatorPII{
		FullName: "Test Applicant", DateOfBirth: "1985-03-04", PostalAddress: "3 Test Street, Kutaisi",
		ContactEmail: "applicant@example.test", ContactPhone: "+995 555 000 003",
	}}
}

// The brief's end to end with the flag on: an application submitted,
// verified by its e-mailed link, reviewed and approved; the operator is
// registered through the registry with a number the policy accepts;
// the approval mail carries the secret part once, the registry holds
// only its hash; the public check answers valid; every step is audited
// and nothing personal is stored in clear.
func TestIntegrationApplicationEndToEnd(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	app, err := it.svc.Submit(ctx, applicant(), "ka", "192.0.2.10")
	if err != nil || app.State != StateUnverified {
		t.Fatalf("submit %+v %v", app, err)
	}
	if n := it.count(t, `SELECT count(*) FROM registry_applications WHERE position('applicant@example.test' in encode(payload_enc, 'escape')) > 0`); n != 0 {
		t.Fatal("the content is stored in clear")
	}
	// Queued, not sent, until the sender runs after the commit.
	if len(it.mail.msgs) != 0 {
		t.Fatal("mailed inside the transaction")
	}
	if s := it.send(t); s.Sent != 1 {
		t.Fatalf("sent %+v", s)
	}
	verifyMail := it.mail.last(t)
	if verifyMail.to != "applicant@example.test" || !strings.Contains(verifyMail.body, "https://portal.example.test/registry/applications/"+app.ID+"#token=") {
		t.Fatalf("%+v", verifyMail)
	}
	if n := it.count(t, `SELECT count(*) FROM registry_portal_mail WHERE message_enc IS NULL AND sent_at IS NOT NULL`); n != 1 {
		t.Fatal("the sent message's content was not cleared")
	}
	tok := tokenOf(t, verifyMail.body)
	// A token of another application, or none, is 404.
	if _, err := it.svc.Verify(ctx, strings.Repeat("0", 32), tok); httpx.ProblemFromError(err).Status != http.StatusNotFound {
		t.Fatalf("other id: %v", err)
	}
	if _, err := it.svc.Status(ctx, app.ID, "v1.x.y"); httpx.ProblemFromError(err).Status != http.StatusNotFound {
		t.Fatalf("bad token: %v", err)
	}
	v, err := it.svc.Verify(ctx, app.ID, tok)
	if err != nil || v.State != StateSubmitted {
		t.Fatalf("verify %+v %v", v, err)
	}
	if again, err := it.svc.Verify(ctx, app.ID, tok); err != nil || again.State != StateSubmitted {
		t.Fatalf("verify again %+v %v", again, err)
	}
	if _, err := it.svc.Approve(ctx, app.ID, nil, registrar); httpx.ProblemFromError(err).Status != http.StatusConflict {
		t.Fatalf("approved before review: %v", err)
	}
	if _, err := it.svc.PersonalData(ctx, app.ID, "", registrar); httpx.ProblemFromError(err).Status != http.StatusBadRequest {
		t.Fatalf("read without a purpose: %v", err)
	}
	content, err := it.svc.PersonalData(ctx, app.ID, "registration review", registrar)
	if err != nil || content.PII.FullName != "Test Applicant" {
		t.Fatalf("content %+v %v", content, err)
	}
	if _, err := it.svc.StartReview(ctx, app.ID, registrar); err != nil {
		t.Fatal(err)
	}
	approved, err := it.svc.Approve(ctx, app.ID, nil, registrar)
	if err != nil || approved.State != StateApproved || approved.OperatorID == "" {
		t.Fatalf("approve %+v %v", approved, err)
	}
	if !regexp.MustCompile(`^GEO[0-9a-z]{12}$`).MatchString(approved.IssuedNumber) {
		t.Fatalf("issued %q", approved.IssuedNumber)
	}
	if n := it.count(t, `SELECT count(*) FROM uas_operators WHERE id = $1 AND source = 'portal' AND source_ref = $2 AND secret_part_hash IS NOT NULL`,
		approved.OperatorID, app.ID); n != 1 {
		t.Fatal("the operator is not registered from the portal")
	}
	if n := it.count(t, `SELECT count(*) FROM registry_applications WHERE secret_enc IS NOT NULL`); n != 0 {
		t.Fatal("the secret part outlived the approval on the application")
	}
	if s := it.send(t); s.Sent != 1 {
		t.Fatalf("sent %+v", s)
	}
	approval := it.mail.last(t)
	secret := regexp.MustCompile(approved.IssuedNumber + `-([0-9a-z]{3})`).FindStringSubmatch(approval.body)
	if secret == nil || !strings.Contains(approval.subject, "რეგისტრაცია") {
		t.Fatalf("approval mail %+v", approval)
	}
	// The secret part is the registry's: the hash matches what was mailed.
	op, err := it.reg.Service.ListOperators(ctx, approved.IssuedNumber, "", registry.Page{})
	if err != nil || len(op) != 1 || !op[0].HasSecretPart {
		t.Fatalf("%+v %v", op, err)
	}
	if n := it.count(t, `SELECT count(*) FROM events WHERE payload::text LIKE '%' || $1 || '%'`, secret[1]+`"`); n != 0 {
		t.Fatal("the secret part reached the audit log")
	}
	check, err := it.reg.Service.CheckNumber(ctx, approved.IssuedNumber+"-"+secret[1])
	if err != nil || check.Status != registry.ValidityValid {
		t.Fatalf("check %+v %v", check, err)
	}
	st, err := it.svc.Status(ctx, app.ID, tokenOf(t, approval.body))
	if err != nil || st.State != StateApproved || st.IssuedNumber != approved.IssuedNumber {
		t.Fatalf("status %+v %v", st, err)
	}
	for _, ev := range []string{"registry_application_submitted", "registry_application_verified", "registry_application_pii_viewed",
		"registry_application_review_started", "registry_application_approved", "operator_registered", "registry_portal_mail_sent"} {
		if n := it.count(t, `SELECT count(*) FROM events WHERE event_type = $1`, ev); n == 0 {
			t.Errorf("no %s event", ev)
		}
	}
	if n := it.count(t, `SELECT count(*) FROM events WHERE payload::text LIKE '%applicant@example.test%' OR payload::text LIKE '%Test Applicant%'`); n != 0 {
		t.Fatalf("%d events hold personal data", n)
	}
	// A retried registration finds the operator the approval made.
	a := Application{ID: app.ID, IssuedNumber: approved.IssuedNumber, ValidUntil: approved.ValidUntil}
	in := applicant()
	var again registry.Operator
	var collided bool
	err = it.reg.Service.Change(ctx, func(_ *pggen.Queries, w registry.Within) error {
		var err error
		again, collided, err = it.svc.registerOperator(ctx, w, &a, &in, secret[1], registrar)
		return err
	})
	if err != nil || collided || again.ID != approved.OperatorID {
		t.Fatalf("retried registration %+v %v", again, err)
	}
}

// A refusal is mailed with its reason; an expired verification link is
// 409; the purge deletes what its retention ended and keeps the
// operator.
func TestIntegrationRefusalExpiryAndPurge(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	a1, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	it.send(t)
	tok := tokenOf(t, it.mail.last(t).body)
	if _, err := it.admin.ExecContext(ctx, `UPDATE registry_applications SET verify_expires_at = now() - interval '1 second' WHERE id = $1`, a1.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := it.svc.Verify(ctx, a1.ID, tok); httpx.ProblemFromError(err).Slug() != SlugLinkExpired {
		t.Fatalf("expired link: %v", err)
	}
	a2, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.11")
	if err != nil {
		t.Fatal(err)
	}
	it.send(t)
	if _, err := it.svc.Verify(ctx, a2.ID, tokenOf(t, it.mail.last(t).body)); err != nil {
		t.Fatal(err)
	}
	if _, err := it.svc.Refuse(ctx, a2.ID, "", registrar); err == nil {
		t.Fatal("refused without a reason")
	}
	r, err := it.svc.Refuse(ctx, a2.ID, "insurance missing", registrar)
	if err != nil || r.State != StateRefused {
		t.Fatalf("%+v %v", r, err)
	}
	it.send(t)
	if m := it.mail.last(t); !strings.Contains(m.body, "insurance missing") {
		t.Fatalf("%+v", m)
	}
	// Nothing past its retention yet: the purge deletes nothing.
	if p, err := it.svc.Purge(ctx); err != nil || p.Applications != 0 {
		t.Fatalf("early purge %+v %v", p, err)
	}
	if _, err := it.admin.ExecContext(ctx, `UPDATE registry_applications SET decided_at = now() - interval '2 days' WHERE id = $1`, a2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := it.admin.ExecContext(ctx, `UPDATE registry_applications SET verify_expires_at = now() - interval '2 hours' WHERE id = $1`, a1.ID); err != nil {
		t.Fatal(err)
	}
	p, err := it.svc.Purge(ctx)
	if err != nil || p.Applications != 2 {
		t.Fatalf("purge %+v %v", p, err)
	}
	if n := it.count(t, `SELECT count(*) FROM registry_applications`); n != 0 {
		t.Fatalf("%d applications left", n)
	}
	if n := it.count(t, `SELECT count(*) FROM events WHERE event_type = 'registry_applications_purged'`); n != 1 {
		t.Fatal("the purge is not audited")
	}
}

// E-10: the per-address budget of applications is held in the database
// across instances: past it 429 with a Retry-After; another address is
// not touched.
func TestIntegrationApplicationBudgetPerAddress(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	for i := range 3 {
		if _, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.20"); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	_, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.20")
	var be *BudgetSpentError
	if !errors.As(err, &be) || be.RetryAfter < time.Second || it.svc.Counters.Get(CounterBudgetSpent) != 1 {
		t.Fatalf("past the budget: %v", err)
	}
	if _, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.21"); err != nil {
		t.Fatalf("another address: %v", err)
	}
	// A refused submission stored nothing: four applications in all.
	if n := it.count(t, `SELECT count(*) FROM registry_applications`); n != 4 {
		t.Fatalf("%d applications", n)
	}
	// An invalid application is refused before the budget is spent.
	bad := applicant()
	bad.PII.ContactEmail = "x"
	if _, err := it.svc.Submit(ctx, bad, "en", "192.0.2.22"); httpx.ProblemFromError(err).Status != http.StatusBadRequest {
		t.Fatalf("invalid: %v", err)
	}
	if n := it.count(t, `SELECT count(*) FROM registry_portal_hits`); n != 4 {
		t.Fatalf("%d hits", n)
	}
}

// Mail failures: a transient one waits for its retry and is given up
// after the attempts; a permanent one at once; both clear the content.
func TestIntegrationMailRetryAndGiveUp(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	if _, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.30"); err != nil {
		t.Fatal(err)
	}
	it.mail.err = errors.New("relay down")
	if s := it.send(t); s.Retried != 1 {
		t.Fatalf("%+v", s)
	}
	if s := it.send(t); s.Retried+s.Failed != 0 {
		t.Fatalf("retried before its time: %+v", s)
	}
	if _, err := it.admin.ExecContext(ctx, `UPDATE registry_portal_mail SET next_attempt_at = now()`); err != nil {
		t.Fatal(err)
	}
	if s := it.send(t); s.Failed != 1 {
		t.Fatalf("%+v", s)
	}
	if _, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.30"); err != nil {
		t.Fatal(err)
	}
	it.mail.err = &PermanentError{Err: errors.New("550 no such user")}
	if s := it.send(t); s.Failed != 1 {
		t.Fatalf("permanent: %+v", s)
	}
	if n := it.count(t, `SELECT count(*) FROM registry_portal_mail WHERE failed_at IS NOT NULL AND message_enc IS NULL`); n != 2 {
		t.Fatalf("%d failed and cleared", n)
	}
	if n := it.count(t, `SELECT count(*) FROM events WHERE event_type = 'registry_portal_mail_failed'`); n != 2 {
		t.Fatal("the give-ups are not audited")
	}
}

// An operator's link: mailed only to the registered address of a
// registration in good standing, answered alike for any number, good
// for one report, which reaches WP-18's intake as operator:<public part>.
func TestIntegrationOperatorLink(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	op, err := it.reg.Service.CreateOperator(ctx, registry.NewOperator{
		OperatorType: registry.OperatorNatural, RegistrationNumber: "GEOTEST00000001",
		PII: registry.OperatorPII{FullName: "Test Person", DateOfBirth: "1980-01-02", PostalAddress: "1 Test Street",
			ContactEmail: "operator@example.test", ContactPhone: "+995 555 000 001"},
		ValidUntil: time.Now().AddDate(1, 0, 0),
	}, registrar)
	if err != nil {
		t.Fatal(err)
	}
	// An unknown number: answered alike, nothing mailed.
	if err := it.svc.RequestLink(ctx, "GEOTEST00000009", "en", "192.0.2.40"); err != nil {
		t.Fatal(err)
	}
	if s := it.send(t); s.Sent != 0 || it.svc.Counters.Get(CounterLinksUnmailed) != 1 {
		t.Fatalf("mailed for an unknown number: %+v", s)
	}
	if err := it.svc.RequestLink(ctx, "geotest00000001-abc", "en", "192.0.2.40"); err != nil {
		t.Fatal(err)
	}
	if s := it.send(t); s.Sent != 1 {
		t.Fatalf("%+v", s)
	}
	m := it.mail.last(t)
	if m.to != "operator@example.test" {
		t.Fatalf("%+v", m)
	}
	tok := tokenOf(t, m.body)
	body := &gen.OccurrenceReport{Schema: "occurrence/v1", ReportRef: "TEST-OP-REPORT-1", Channel: "voluntary",
		OccurredAt: time.Now().Add(-time.Hour).UTC(), BecameAwareAt: time.Now().Add(-30 * time.Minute).UTC(), Category: "other"}
	// A bad body spends nothing.
	if _, err := it.svc.ReportOccurrence(ctx, tok, &gen.OccurrenceReport{}); httpx.ProblemFromError(err).Status != http.StatusBadRequest {
		t.Fatalf("bad body: %v", err)
	}
	rc, err := it.svc.ReportOccurrence(ctx, tok, body)
	if err != nil || rc.Report.ReportRef != "TEST-OP-REPORT-1" {
		t.Fatalf("%+v %v", rc, err)
	}
	if len(it.occ.origins) != 1 || it.occ.origins[0].Org != "operator:"+op.RegistrationNumber || !it.occ.origins[0].Operator {
		t.Fatalf("origin %+v", it.occ.origins)
	}
	if _, err := it.svc.ReportOccurrence(ctx, tok, body); httpx.ProblemFromError(err).Slug() != SlugLinkSpent {
		t.Fatalf("second use: %v", err)
	}
	if _, err := it.svc.ReportOccurrence(ctx, tok+"x", body); httpx.ProblemFromError(err).Status != http.StatusUnauthorized {
		t.Fatalf("forged: %v", err)
	}
	// The operator's own budget (2 per window): the third request is
	// answered alike and mails nothing.
	_ = it.svc.RequestLink(ctx, "GEOTEST00000001", "en", "192.0.2.41")
	before := it.svc.Counters.Get(CounterLinksUnmailed)
	if err := it.svc.RequestLink(ctx, "GEOTEST00000001", "en", "192.0.2.42"); err != nil {
		t.Fatal(err)
	}
	if it.svc.Counters.Get(CounterLinksUnmailed) != before+1 {
		t.Fatal("the operator's budget did not hold")
	}
	// A suspended operator is sent no link.
	if _, err := it.reg.Service.SetOperatorStatus(ctx, op.ID, registry.StatusSuspended, "test", registrar); err != nil {
		t.Fatal(err)
	}
	if _, err := it.admin.ExecContext(ctx, `DELETE FROM registry_portal_hits WHERE bucket = 'operator_link_operator'`); err != nil {
		t.Fatal(err)
	}
	sentBefore := it.send(t).Sent
	_ = it.svc.RequestLink(ctx, "GEOTEST00000001", "en", "192.0.2.43")
	if s := it.send(t); s.Sent != 0 || sentBefore < 0 {
		t.Fatalf("a suspended operator was mailed: %+v", s)
	}
	if n := it.count(t, `SELECT count(*) FROM events WHERE event_type = 'registry_operator_link_used'`); n != 1 {
		t.Fatalf("%d link uses", n)
	}
}

// Nothing slow inside a transaction: while a message is being handed to
// the relay the sender holds no transaction open and no row locked, and
// every message delivered before it is committed as sent already.
func TestIntegrationMailCommitsPerMessage(t *testing.T) {
	it := newIntegration(t)
	ctx := context.Background()
	for i := range 3 {
		if _, err := it.svc.Submit(ctx, applicant(), "en", fmt.Sprintf("192.0.2.%d", 80+i)); err != nil {
			t.Fatal(err)
		}
	}
	delivering := 0
	it.mail.during = func() {
		delivering++
		if n := it.count(t, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()
			AND application_name = 'uspace-authority-test' AND state LIKE 'idle in transaction%'`); n != 0 {
			t.Errorf("delivery %d: %d transactions open", delivering, n)
		}
		if _, err := it.admin.ExecContext(ctx, `SELECT id FROM registry_portal_mail FOR UPDATE NOWAIT`); err != nil {
			t.Errorf("delivery %d: a mail row is locked: %v", delivering, err)
		}
		if n := it.count(t, `SELECT count(*) FROM registry_portal_mail WHERE sent_at IS NOT NULL`); n != delivering-1 {
			t.Errorf("delivery %d: %d messages committed as sent, want %d", delivering, n, delivering-1)
		}
	}
	if s := it.send(t); s.Sent != 3 || delivering != 3 {
		t.Fatalf("sent %+v in %d deliveries", s, delivering)
	}
	// A claimed message is leased: another sender does not take it until
	// its lease ends; past it, it is due again.
	if _, err := it.svc.Submit(ctx, applicant(), "en", "192.0.2.84"); err != nil {
		t.Fatal(err)
	}
	if _, err := it.svc.DB.Queries().ClaimPortalMail(ctx, 60); err != nil {
		t.Fatal(err)
	}
	if s := it.send(t); s.Sent != 0 {
		t.Fatalf("a leased message was sent again: %+v", s)
	}
	if _, err := it.admin.ExecContext(ctx, `UPDATE registry_portal_mail SET next_attempt_at = now() WHERE sent_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if s := it.send(t); s.Sent != 1 {
		t.Fatalf("past its lease: %+v", s)
	}
}
