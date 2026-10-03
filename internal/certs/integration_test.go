package certs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/bus"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/certkv"
	"github.com/rootxkit/uspace-authority/internal/cisp"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/policy"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
	"github.com/rootxkit/uspace-authority/internal/tokens"
	"github.com/rootxkit/uspace-authority/internal/tokens/tokentest"
)

const issuer = "https://authority.example.test"

var admin = audit.Actor{Type: audit.ActorUser, ID: "admin-1", Realm: audit.RealmConsole}

type rig struct {
	svc *Service
	sql *sql.DB
	kv  jetstream.KeyValue
	db  *pgstore.DB
	u   string
}

// newRig is a Service on a migrated relational database, WP-6's real
// outbox (the pinned schemas, a publication key generated now) and a
// KV bucket of its own; outbox false leaves the list pending.
func newRig(t *testing.T, outbox bool) *rig {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	db, err := pgstore.Open(context.Background(), store.PoolOptions{URL: u, Role: pgstore.AppRole})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	_, js := bustest.Connect(t)
	cfg := certkv.BucketConfig(bustest.Name("certs"))
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), cfg.Bucket) })
	kv, err := bus.OpenBucket(context.Background(), js, cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{sql: storetest.Open(t, u), kv: kv, db: db, u: u}
	r.svc = r.service(t, outbox)
	return r
}

// service is a fresh Service on the rig's database and bucket: a second
// one is another api replica (another instance, nothing shared but the
// database and the bus).
func (r *rig) service(t *testing.T, outbox bool) *Service {
	t.Helper()
	w := audit.NewWriter(r.db)
	hasher, err := passhash.New(passhash.Params{MemoryKiB: 64, Time: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	cnt := &core.Counters{}
	s := &Service{
		DB: r.db, Audit: w, Clients: &tokens.Registry{Store: tokens.PG{DB: r.db, Audit: w}, Hasher: hasher},
		KV: func(context.Context) (jetstream.KeyValue, error) { return r.kv, nil }, KVTimeout: 2 * time.Second,
		Policy: func() (policy.Policy, bool) { return policy.Policy{Version: 1, Thresholds: policy.Defaults()}, true },
		Issuer: issuer, Audiences: []string{"authority.example.test", "cisp.example.test"}, TokenTTL: time.Hour,
		Counters: cnt, Logger: logging.Discard(), Limiter: logging.NewLimiter(logging.Discard(), time.Minute, 0, cnt),
	}
	if outbox {
		schemas, err := cisp.LoadSchemas()
		if err != nil {
			t.Fatal(err)
		}
		ring, err := auth.NewKeyRing(auth.SigningKey{KID: "publication-1", Key: tokentest.Key(t, 9)})
		if err != nil {
			t.Fatal(err)
		}
		s.Outbox = cisp.NewOutbox(schemas, ring, cisp.PG{DB: r.db, Audit: w}, nil)
	}
	return s
}

func ussp(code string) IssueInput {
	lc := strings.ToLower(code)
	return IssueInput{
		Holder: HolderUSSP, HolderName: "USSP " + code, HolderEmail: "ops@" + lc + ".example.test", HolderURL: "https://" + lc + ".example.test/contact",
		Code: code, BaseURL: "https://" + lc + ".example.test", TermsURL: "https://" + lc + ".example.test/terms",
		Services:   []string{ServiceNetworkIdentification, ServiceGeoAwareness, ServiceFlightAuthorisation, ServiceTrafficInformation},
		ValidUntil: time.Now().AddDate(2, 0, 0), AuthMethod: tokens.MethodSecretPost,
	}
}

func (r *rig) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := r.sql.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (r *rig) clientStatus(t *testing.T, id string) string {
	t.Helper()
	var s string
	if err := r.sql.QueryRow(`SELECT status FROM oauth_clients WHERE client_id = $1`, id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// lastList is the newest ussp_list row of the outbox, decoded.
func (r *rig) lastList(t *testing.T) USSPList {
	t.Helper()
	var raw []byte
	if err := r.sql.QueryRow(`SELECT payload FROM publications WHERE dataset = 'ussp_list' ORDER BY id DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var l USSPList
	if err := json.Unmarshal(raw, &l); err != nil {
		t.Fatal(err)
	}
	return l
}

func codes(l USSPList) []string {
	out := []string{}
	for i := range l.USSPs {
		out = append(out, l.USSPs[i].USSPID)
	}
	return out
}

func (r *rig) kvClients(t *testing.T) []string {
	t.Helper()
	e, err := r.kv.Get(context.Background(), certkv.Key)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := certkv.Decode(e.Value())
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, u := range reg.USSPs {
		out = append(out, u.ClientID)
	}
	return out
}

func problem(t *testing.T, err error) *httpx.Problem {
	t.Helper()
	if err == nil {
		t.Fatal("no error")
	}
	return httpx.ProblemFromError(err)
}

// The lifecycle: issue registers the client with the derived scopes;
// a code taken or malformed is refused beside the accepted one; the
// holder's own client starts operations (another client refused beside
// it) and the list is queued with it and KV carries it; a retried notice
// is the same notice; a suspension suspends the client, says until when
// its tokens run and takes the USSP off the list and KV; a
// reinstatement brings both back; a limitation travels on the list;
// revocation is final.
func TestIntegrationCertificateLifecycle(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	s := r.svc

	is, err := s.Issue(ctx, ussp("AB12"), admin)
	if err != nil {
		t.Fatal(err)
	}
	c := is.Certificate
	if c.Status != StatusIssued || c.ClientID != "ussp-AB12-01" || is.Secret == "" || c.LapseUnusedAfterMonths != 6 || c.LapseCeasedAfterMonths != 12 {
		t.Fatalf("%+v", is)
	}
	if want := ScopesFor(HolderUSSP, c.Services); !slices.Equal(is.Client.Scopes, want) || is.Client.Status != tokens.StatusActive ||
		!slices.Equal(is.Client.Audiences, []string{"authority.example.test", "cisp.example.test"}) {
		t.Fatalf("client %+v", is.Client)
	}
	if n := r.count(t, `SELECT count(*) FROM oauth_clients WHERE client_id = 'ussp-AB12-01' AND certificate_id = $1`, c.ID); n != 1 {
		t.Fatal("the client is not linked to its certificate")
	}
	if n := r.count(t, `SELECT count(*) FROM events WHERE event_type IN ('certificate_issued', 'oauth_client_created') AND actor_id = 'admin-1'`); n != 2 {
		t.Fatalf("%d issue events", n)
	}
	// E-01: the code taken, or malformed, beside the accepted one.
	if p := problem(t, func() error { _, err := s.Issue(ctx, ussp("AB12"), admin); return err }()); p.Status != http.StatusConflict ||
		p.Slug() != SlugCodeTaken {
		t.Fatalf("%+v", p)
	}
	for _, bad := range []string{"ab12", "ABCDEFGHI", "AB-1"} {
		if p := problem(t, func() error { _, err := s.Issue(ctx, ussp(bad), admin); return err }()); p.Status != http.StatusBadRequest {
			t.Fatalf("%s: %+v", bad, p)
		}
	}
	if n := r.count(t, `SELECT count(*) FROM certificates`); n != 1 {
		t.Fatalf("%d certificates after the refusals", n)
	}
	if got := r.kvClients(t); len(got) != 0 {
		t.Fatalf("an issued certificate is in KV: %v", got)
	}

	// The start of operations: another client refused, the holder's
	// own accepted.
	start := NoticeInput{State: NoticeStarted, At: time.Now(), Reference: "OPS-1"}
	if p := problem(t, func() error {
		_, err := s.RecordNotice(ctx, c.ID, start, SourceMachine, &Caller{Subject: "ussp-ZZ99-01", Issuer: issuer}, auditClient("ussp-ZZ99-01"))
		return err
	}()); p.Status != http.StatusForbidden || p.Slug() != SlugWrongClient {
		t.Fatalf("%+v", p)
	}
	if p := problem(t, func() error {
		_, err := s.RecordNotice(ctx, c.ID, start, SourceMachine, &Caller{Subject: c.ClientID, Issuer: "https://lab.example.test"}, auditClient(c.ClientID))
		return err
	}()); p.Status != http.StatusForbidden {
		t.Fatalf("another issuer's token: %+v", p)
	}
	n, err := s.RecordNotice(ctx, c.ID, start, SourceMachine, &Caller{Subject: c.ClientID, Issuer: issuer}, auditClient(c.ClientID))
	if err != nil || n.Replayed || n.Certificate.Status != StatusOperating || n.List.State != PubQueued {
		t.Fatalf("%+v %v", n, err)
	}
	if got := codes(r.lastList(t)); !slices.Equal(got, []string{"AB12"}) {
		t.Fatalf("list %v", got)
	}
	if got := r.kvClients(t); !slices.Equal(got, []string{"ussp-AB12-01"}) {
		t.Fatalf("kv %v", got)
	}
	again, err := s.RecordNotice(ctx, c.ID, start, SourceMachine, &Caller{Subject: c.ClientID, Issuer: issuer}, auditClient(c.ClientID))
	if err != nil || !again.Replayed || again.Notice.ID != n.Notice.ID {
		t.Fatalf("a retried notice: %+v %v", again, err)
	}
	if p := problem(t, func() error {
		_, err := s.RecordNotice(ctx, c.ID, NoticeInput{State: NoticeCeased, At: time.Now(), Reference: "OPS-1"}, SourceMachine,
			&Caller{Subject: c.ClientID, Issuer: issuer}, auditClient(c.ClientID))
		return err
	}()); p.Status != http.StatusConflict || p.Slug() != SlugNoticeReference {
		t.Fatalf("a reused reference: %+v", p)
	}
	if p := problem(t, func() error {
		_, err := s.RecordNotice(ctx, c.ID, NoticeInput{State: NoticeStarted, At: time.Now()}, SourceMachine,
			&Caller{Subject: c.ClientID, Issuer: issuer}, auditClient(c.ClientID))
		return err
	}()); p.Status != http.StatusConflict || p.Slug() != SlugTransition {
		t.Fatalf("started twice: %+v", p)
	}

	// Suspension: the client at once, the list and KV without it.
	before := r.count(t, `SELECT count(*) FROM publications WHERE dataset = 'ussp_list'`)
	ch, err := s.Transition(ctx, c.ID, ActionSuspend, "audit finding 7", nil, admin)
	if err != nil || ch.Certificate.Status != StatusSuspended || ch.ClientStatus != tokens.StatusSuspended || ch.TokensValidUntil == nil ||
		ch.TokensValidUntil.Before(time.Now().Add(50*time.Minute)) || ch.List.State != PubQueued {
		t.Fatalf("%+v %v", ch, err)
	}
	if r.clientStatus(t, c.ClientID) != tokens.StatusSuspended || r.count(t, `SELECT count(*) FROM publications WHERE dataset = 'ussp_list'`) != before+1 {
		t.Fatal("suspension did not reach the client or the list")
	}
	if got := codes(r.lastList(t)); len(got) != 0 {
		t.Fatalf("a suspended USSP is listed: %v", got)
	}
	if got := r.kvClients(t); len(got) != 0 {
		t.Fatalf("a suspended USSP is in KV: %v", got)
	}
	if p := problem(t, func() error { _, err := s.Transition(ctx, c.ID, ActionSuspend, "again", nil, admin); return err }()); p.Status != http.StatusConflict {
		t.Fatalf("suspended twice: %+v", p)
	}
	// Starting while suspended is refused; ceasing is recorded.
	if p := problem(t, func() error {
		_, err := s.RecordNotice(ctx, c.ID, NoticeInput{State: NoticeRestarted, At: time.Now(), Reference: "L-9"}, SourceManual, nil, admin)
		return err
	}()); p.Status != http.StatusConflict {
		t.Fatalf("%+v", p)
	}

	ch, err = s.Transition(ctx, c.ID, ActionReinstate, "finding closed", nil, admin)
	if err != nil || ch.Certificate.Status != StatusOperating || ch.ClientStatus != tokens.StatusActive || r.clientStatus(t, c.ClientID) != tokens.StatusActive {
		t.Fatalf("%+v %v", ch, err)
	}
	if got := codes(r.lastList(t)); !slices.Equal(got, []string{"AB12"}) {
		t.Fatalf("list after reinstatement %v", got)
	}
	ch, err = s.Transition(ctx, c.ID, ActionLimit, "VLOS only", []string{"VLOS operations only"}, admin)
	if err != nil || ch.Certificate.Status != StatusLimited || ch.ClientStatus != "" {
		t.Fatalf("%+v %v", ch, err)
	}
	if l := r.lastList(t); len(l.USSPs) != 1 || l.USSPs[0].Status != StatusLimited || !slices.Equal(l.USSPs[0].CertificationLimitations, []string{"VLOS operations only"}) {
		t.Fatalf("limited list %+v", l)
	}
	if p := problem(t, func() error { _, err := s.Transition(ctx, c.ID, ActionLimit, "x", []string{"y"}, admin); return err }()); p.Status != http.StatusConflict {
		t.Fatalf("limited twice: %+v", p)
	}
	ch, err = s.Transition(ctx, c.ID, ActionRevoke, "certificate withdrawn", nil, admin)
	if err != nil || ch.Certificate.Status != StatusRevoked || r.clientStatus(t, c.ClientID) != tokens.StatusRevoked || len(codes(r.lastList(t))) != 0 {
		t.Fatalf("%+v %v", ch, err)
	}
	if p := problem(t, func() error { _, err := s.Transition(ctx, c.ID, ActionReinstate, "x", nil, admin); return err }()); p.Status != http.StatusConflict {
		t.Fatalf("a revoked certificate reinstated: %+v", p)
	}
	// Every transition with its actor and reason.
	if n := r.count(t, `SELECT count(*) FROM events WHERE event_type = 'certificate_status_changed' AND entity_id = $1 AND actor_id = 'admin-1'
		AND payload->>'reason' <> ''`, c.ID); n != 4 {
		t.Fatalf("%d transitions recorded", n)
	}
	// The database refuses to bring a revoked certificate back.
	if _, err := r.sql.Exec(`UPDATE certificates SET ended = NULL WHERE id = $1`, c.ID); err == nil {
		t.Fatal("a revoked certificate changed status in the database")
	}
}

func auditClient(id string) audit.Actor { return audit.Actor{Type: audit.ActorClient, ID: id} }

// The lapse job on backdated certificates (Art. 16(2), E-01): one never
// used for seven months and one ceased thirteen months ago lapse, with
// their clients revoked and the rule named; one five months unused and
// one ceased eleven months ago do not; a second run lapses nothing; a
// replica finding the job's lock held skips.
func TestIntegrationLapseJobOnBackdatedRows(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()
	s := r.svc
	issue := func(code string, ago time.Duration) certRef {
		in := ussp(code)
		from := time.Now().Add(-ago)
		in.ValidFrom = &from
		is, err := s.Issue(ctx, in, admin)
		if err != nil {
			t.Fatal(err)
		}
		return certRef{id: is.Certificate.ID, client: is.Certificate.ClientID}
	}
	month := 30 * 24 * time.Hour
	unused7 := issue("UNUSED7", 7*month)
	unused5 := issue("UNUSED5", 5*month)
	ceased13 := issue("CEASED13", 20*month)
	ceased11 := issue("CEASED11", 20*month)
	notice := func(id, state string, ago time.Duration) {
		if _, err := s.RecordNotice(ctx, id, NoticeInput{State: state, At: time.Now().Add(-ago), Reference: id[:6] + state}, SourceManual, nil, admin); err != nil {
			t.Fatal(err)
		}
	}
	notice(ceased13.id, NoticeStarted, 19*month)
	notice(ceased13.id, NoticeCeased, 13*month)
	notice(ceased11.id, NoticeStarted, 19*month)
	notice(ceased11.id, NoticeCeased, 11*month)

	// Another replica holds the job's lock: this one skips.
	tx, err := r.sql.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, lockLapse); err != nil {
		t.Fatal(err)
	}
	if lapsed, ran, err := s.Lapse(ctx); err != nil || ran || len(lapsed) != 0 {
		t.Fatalf("ran beside a running job: %v %v %v", lapsed, ran, err)
	}
	_ = tx.Rollback()

	lapsed, ran, err := s.Lapse(ctx)
	if err != nil || !ran {
		t.Fatal(ran, err)
	}
	got := map[string]string{}
	for _, c := range lapsed {
		got[c.ID] = c.StatusReason
	}
	if len(got) != 2 || !strings.HasPrefix(got[unused7.id], RuleUnused) || !strings.HasPrefix(got[ceased13.id], RuleCeased) {
		t.Fatalf("lapsed %v", got)
	}
	for _, c := range []certRef{unused7, ceased13} {
		if r.clientStatus(t, c.client) != tokens.StatusRevoked {
			t.Errorf("%s: client not revoked", c.client)
		}
	}
	for _, c := range []certRef{unused5, ceased11} {
		if r.clientStatus(t, c.client) != tokens.StatusActive || r.count(t, `SELECT count(*) FROM certificates WHERE id = $1 AND ended IS NULL`, c.id) != 1 {
			t.Errorf("%s lapsed", c.client)
		}
	}
	if n := r.count(t, `SELECT count(*) FROM events WHERE event_type = 'certificate_status_changed' AND payload->>'action' = 'lapse'
		AND payload->>'rule' IN ('lapse_unused', 'lapse_ceased') AND actor_type = 'system'`); n != 2 {
		t.Fatalf("%d lapse events", n)
	}
	if again, ran, err := s.Lapse(ctx); err != nil || !ran || len(again) != 0 {
		t.Fatalf("a second run: %v %v %v", again, ran, err)
	}
}

type certRef struct{ id, client string }

// A list that could not be queued (no publication key) is pending in
// the database; another replica's repair queues it; and a certificate
// that leaves the list by expiry, without any write, is taken off it by
// the repair (never forget a missed clear).
func TestIntegrationListRepairAcrossReplicas(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	in := ussp("EXP1")
	in.ValidUntil = time.Now().Add(4 * time.Second)
	is, err := r.svc.Issue(ctx, in, admin)
	if err != nil {
		t.Fatal(err)
	}
	n, err := r.svc.RecordNotice(ctx, is.Certificate.ID, NoticeInput{State: NoticeStarted, At: time.Now(), Reference: "L-1"}, SourceManual, nil, admin)
	if err != nil || n.List.State != PubPending || !strings.Contains(n.List.Reason, "outbox") {
		t.Fatalf("%+v %v", n, err)
	}
	if r.count(t, `SELECT count(*) FROM publications`) != 0 || r.count(t, `SELECT count(*) FROM certificate_list_state WHERE wanted > enqueued`) != 1 {
		t.Fatal("the pending list is not recorded")
	}
	other := r.service(t, true)
	queued, err := other.RepairList(ctx)
	if err != nil || !queued {
		t.Fatal(queued, err)
	}
	if got := codes(r.lastList(t)); !slices.Equal(got, []string{"EXP1"}) {
		t.Fatalf("list %v", got)
	}
	if queued, err := other.RepairList(ctx); err != nil || queued {
		t.Fatalf("nothing to repair, queued %v %v", queued, err)
	}
	// The certificate expires: the repair takes it off the list.
	deadline := time.Now().Add(20 * time.Second)
	for {
		queued, err := other.RepairList(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the expired certificate was never taken off the list")
		}
		waitFor(ctx, 100*time.Millisecond)
	}
	if got := codes(r.lastList(t)); len(got) != 0 {
		t.Fatalf("an expired USSP is listed: %v", got)
	}
}

// waitFor blocks for d unless ctx ends: the poll interval of a loop that
// waits for a condition with a deadline.
func waitFor(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// E-02: without an active policy nothing is issued, and it says why.
func TestIntegrationIssueWithoutPolicyIsRefused(t *testing.T) {
	r := newRig(t, true)
	r.svc.Policy = func() (policy.Policy, bool) { return policy.Policy{}, false }
	_, err := r.svc.Issue(context.Background(), ussp("NOPOL"), audit.Actor{Type: audit.ActorUser, ID: "admin-1"})
	var pe *httpx.ProblemError
	if !errors.As(err, &pe) || pe.Problem.Status != http.StatusServiceUnavailable || pe.Problem.Slug() != SlugPolicyUnknown {
		t.Fatalf("%v", err)
	}
	if r.count(t, `SELECT count(*) FROM certificates`)+r.count(t, `SELECT count(*) FROM oauth_clients`) != 0 {
		t.Fatal("something was written")
	}
}
