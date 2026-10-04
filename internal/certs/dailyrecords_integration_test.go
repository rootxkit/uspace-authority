package certs

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/incidents"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

type staticToken struct{}

func (staticToken) Token(context.Context, string, ...string) (string, error) {
	return "test-token", nil
}

// fakeUSSP serves GET /v1/records/daily/{date} for every day but the
// missing ones, and only with the token.
type fakeUSSP struct {
	mu      sync.Mutex
	missing map[string]bool
	reads   []string
}

func (u *fakeUSSP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	day, ok := strings.CutPrefix(r.URL.Path, "/v1/records/daily/")
	if !ok || r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer test-token" {
		http.Error(w, "no", http.StatusForbidden)
		return
	}
	u.mu.Lock()
	u.reads = append(u.reads, day)
	miss := u.missing[day]
	u.mu.Unlock()
	if miss {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"date":"` + day + `","flights":[]}`))
}

// WP-27, spec 02 F7 (plan Q-A18): every operating USSP's daily bundle
// is pulled into the archive store, read back and recorded (presence); a
// day the USSP does not serve is retried each run, and once its grace
// period has passed it is an alarm, once (an events row, a counter, the
// status line); a day inside the grace period is not an alarm yet
// (absence). The alarm survives a restart and clears when the day is
// fetched.
func TestIntegrationDailyRecordsArePulledAndAMissingDayIsAnAlarm(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	u := &fakeUSSP{missing: map[string]bool{}}
	srv := httptest.NewServer(u)
	t.Cleanup(srv.Close)
	in := ussp("ABC")
	in.BaseURL = srv.URL
	is, err := r.svc.Issue(ctx, in, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.RecordNotice(ctx, is.Certificate.ID, NoticeInput{State: NoticeStarted, At: time.Now(), Reference: "S-1"}, SourceManual, nil, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := r.sql.Exec(`UPDATE certificates SET operations_started_at = now() - interval '30 days' WHERE id = $1`, is.Certificate.ID); err != nil {
		t.Fatal(err)
	}
	today := dayOf(time.Now())
	d := func(n int) string { return today.AddDate(0, 0, -n).Format(time.DateOnly) }
	u.missing[d(3)], u.missing[d(1)] = true, true

	store := archive.Dir{Root: t.TempDir()}
	counters := &core.Counters{}
	daily := func() *DailyRecords {
		return &DailyRecords{DB: r.db, Audit: audit.NewWriter(r.db), Store: store, GraceDays: 2, BackfillDays: 5, Timeout: 5 * time.Second,
			MaxBytes: 1 << 20, MaxUSSPs: 10, Counters: counters, Logger: logging.Discard(),
			Fetcher: &incidents.Records{Tokens: staticToken{}, HTTP: srv.Client()}}
	}
	job := daily()
	sum, err := job.RunOnce(ctx)
	if err != nil || sum["days_fetched"] != 3 || sum["days_failed"] != 2 || sum["days_alarmed"] != 1 {
		t.Fatalf("first run %v %v", sum, err)
	}
	if got := sum["missing_days"].([]string); !slices.Equal(got, []string{"ABC/" + d(3)}) {
		t.Fatalf("missing %v (the day inside the grace period is not an alarm)", got)
	}
	if n := r.count(t, `SELECT count(*) FROM events WHERE event_type = $1`, audit.EventUSSPRecordsFetched); n != 3 {
		t.Fatalf("%d fetched rows", n)
	}
	if n := r.count(t, `SELECT count(*) FROM events WHERE event_type = $1 AND entity_id = $2`, audit.EventUSSPRecordsDayMissing, "ABC/"+d(3)); n != 1 {
		t.Fatalf("%d alarm rows", n)
	}
	// What was recorded is what the store holds.
	var key, sha string
	if err := r.sql.QueryRow(`SELECT archive_key, sha256 FROM ussp_daily_records WHERE ussp_code = 'ABC' AND day = $1`, today.AddDate(0, 0, -2)).Scan(&key, &sha); err != nil {
		t.Fatal(err)
	}
	if b, err := archive.Get(store, key, 1<<20); err != nil || archive.Hash(b) != sha || !strings.Contains(string(b), d(2)) {
		t.Fatalf("stored %s %v", b, err)
	}

	// A restart: the alarm is still named before any run.
	restarted := daily()
	if err := restarted.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if got := missingOf(restarted); !slices.Equal(got, []string{"ABC/" + d(3)}) {
		t.Fatalf("after a restart %v", got)
	}
	reads := len(u.reads)
	sum, err = restarted.RunOnce(ctx)
	if err != nil || sum["days_fetched"] != 0 || sum["days_alarmed"] != 0 || len(u.reads) != reads+2 {
		t.Fatalf("second run %v %v (reads %v)", sum, err, u.reads[reads:])
	}
	if n := r.count(t, `SELECT count(*) FROM events WHERE event_type = $1`, audit.EventUSSPRecordsDayMissing); n != 1 {
		t.Fatalf("the alarm repeated: %d rows", n)
	}
	if counters.Get(CounterRecordsDaysMissing) != 1 {
		t.Fatalf("counters %v", counters.Snapshot())
	}

	// The USSP serves the day: fetched, and the alarm clears.
	u.mu.Lock()
	delete(u.missing, d(3))
	u.mu.Unlock()
	sum, err = restarted.RunOnce(ctx)
	if err != nil || sum["days_fetched"] != 1 || len(sum["missing_days"].([]string)) != 0 || len(missingOf(restarted)) != 0 {
		t.Fatalf("third run %v %v", sum, err)
	}
}

// Without an archive store nothing is fetched and every day is missing
// with that reason (said, never a silent success).
func TestIntegrationDailyRecordsWithoutAStoreSayWhy(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	in := ussp("NOS")
	in.BaseURL = "http://127.0.0.1:1"
	is, err := r.svc.Issue(ctx, in, admin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.RecordNotice(ctx, is.Certificate.ID, NoticeInput{State: NoticeStarted, At: time.Now(), Reference: "S-1"}, SourceManual, nil, admin); err != nil {
		t.Fatal(err)
	}
	if _, err := r.sql.Exec(`UPDATE certificates SET operations_started_at = now() - interval '3 days' WHERE id = $1`, is.Certificate.ID); err != nil {
		t.Fatal(err)
	}
	job := &DailyRecords{DB: r.db, Audit: audit.NewWriter(r.db), GraceDays: 1, BackfillDays: 2, Logger: logging.Discard()}
	sum, err := job.RunOnce(ctx)
	if err != nil || sum["days_fetched"] != 0 || sum["days_failed"] != 2 {
		t.Fatalf("%v %v", sum, err)
	}
	var why string
	if err := r.sql.QueryRow(`SELECT last_error FROM ussp_daily_records WHERE ussp_code = 'NOS' ORDER BY day LIMIT 1`).Scan(&why); err != nil ||
		!strings.Contains(why, "ARCHIVE_URL") {
		t.Fatalf("reason %q %v", why, err)
	}
}

func missingOf(d *DailyRecords) []string {
	for _, a := range d.StatusAttrs() {
		if a.Key == "ussp_records_missing" {
			if m, ok := a.Value.Any().([]string); ok {
				return m
			}
		}
	}
	return nil
}
