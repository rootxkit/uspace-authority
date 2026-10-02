package cisp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/ltest/fakecisp"
)

// triggers records the pulls the receiver starts.
type triggers struct {
	mu    sync.Mutex
	hints []Hint
	ds    []Dataset
}

func (tr *triggers) trigger(d Dataset, h Hint) {
	tr.mu.Lock()
	tr.ds, tr.hints = append(tr.ds, d), append(tr.hints, h)
	tr.mu.Unlock()
}

func (tr *triggers) n() int {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return len(tr.ds)
}

// recordingWorld is a world whose receiver records its pulls instead
// of starting them.
func recordingWorld(t *testing.T) (*world, *triggers) {
	t.Helper()
	w := newWorld(t)
	tr := &triggers{}
	w.receiver.cfg.Trigger = tr.trigger
	return w, tr
}

func change(ds, reason string, version int64, pullURL string) map[string]any {
	return map[string]any{
		"schema": "cis/change/v1", "msg_id": "7", "producer": "cisp/deliver-fake", "dataset": ds, "version": version,
		"etag": ETagOf(Dataset(ds), version), "feature_ids": []string{}, "removed_ids": []string{}, "reason": reason,
		"at": time.Now().UTC(), "pull_url": pullURL,
	}
}

func (w *world) post(t *testing.T, token, contentType string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, w.rx.URL+NotificationsPath, strings.NewReader(token))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func signAs(t *testing.T, ring *auth.KeyRing, iss, aud string, body map[string]any) string {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := ring.SignCompact(auth.CompactClaims{Issuer: iss, Audience: aud, Subject: "sub-1", JTI: newJTI()}, b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var jtiSeq atomic.Int64

func newJTI() string { return "jti-" + strconv.FormatInt(jtiSeq.Add(1), 10) }

// From the CISP: a zones publication starts a pull, with the pull_url
// kept when it is https on the CISP's host and port; from the ANSP
// (M5): accepted, counted, and the dataset is read from the configured
// CISP, never from the ANSP's pull_url; from a third issuer, or for
// another audience: refused 401 and counted.
func TestNotificationIssuersAndAudience(t *testing.T) {
	w, tr := recordingWorld(t)
	_, ansp := rings(t)
	pull := w.fake.URL() + "/v1/zones?since_version=0"
	if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", 1, pull)), ContentTypeJOSE); code != http.StatusNoContent {
		t.Fatalf("CISP: %d", code)
	}
	if tr.n() != 1 || tr.ds[0] != DatasetZones || tr.hints[0].PullURL != pull || tr.hints[0].Version != 1 {
		t.Fatalf("%+v", tr.hints)
	}
	code := w.post(t, signAs(t, ansp, "https://ansp.test", "127.0.0.1",
		change("restrictions", "restriction_activated", 3, "https://ansp.test/v1/restrictions/r-1")), ContentTypeJOSE)
	if code != http.StatusNoContent || tr.n() != 2 || tr.ds[1] != DatasetRestrictions || tr.hints[1].PullURL != "" {
		t.Fatalf("ANSP: %d %+v", code, tr.hints)
	}
	if w.count(CounterANSPDirect) != 1 || w.count(CounterPullURLMismatch) != 1 {
		t.Fatalf("ansp %d mismatch %d", w.count(CounterANSPDirect), w.count(CounterPullURLMismatch))
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := auth.NewKeyRing(auth.SigningKey{KID: "other-1", Key: k})
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]string{
		"third issuer":          signAs(t, other, "https://other.test", "127.0.0.1", change("zones", "publication", 2, pull)),
		"third key as the CISP": signAs(t, other, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", 2, pull)),
		"another audience":      signAs(t, w.fake.Ring, fakecisp.Issuer, "ussp.test", change("zones", "publication", 2, pull)),
		"not a JWS":             "not-a-jws",
	}
	for name, tok := range refused {
		if code := w.post(t, tok, ContentTypeJOSE); code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", name, code)
		}
	}
	if tr.n() != 2 || w.count(CounterBadSignature) != uint64(len(refused)) {
		t.Fatalf("pulls %d, refused %d", tr.n(), w.count(CounterBadSignature))
	}
}

// A pull_url on another host, or plain http, or another port, is not
// followed: counted, and the pull still starts against the configured
// CISP (beside the accepted pull_url above).
func TestNotificationPullURLGuard(t *testing.T) {
	w, tr := recordingWorld(t)
	host := strings.TrimPrefix(w.fake.URL(), "https://")
	urls := []string{
		"https://evil.test/v1/zones?since_version=0",
		"http://" + host + "/v1/zones?since_version=0",
		"https://" + strings.Split(host, ":")[0] + ":1/v1/zones?since_version=0",
		"https://user@" + host + "/v1/zones?since_version=0",
	}
	for i, u := range urls {
		if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", int64(i+1), u)), ContentTypeJOSE); code != http.StatusNoContent {
			t.Fatalf("%s: %d", u, code)
		}
	}
	if tr.n() != len(urls) || w.count(CounterPullURLMismatch) != uint64(len(urls)) {
		t.Fatalf("pulls %d, mismatches %d", tr.n(), w.count(CounterPullURLMismatch))
	}
	for _, h := range tr.hints {
		if h.PullURL != "" {
			t.Fatalf("followed %s", h.PullURL)
		}
	}
}

// subscription_test, republished and a reason this receiver does not
// know are acknowledged 204 without a pull (M16); a zones change pulls
// (E-01 pair). A repeated delivery id is acknowledged and not acted on.
func TestNotificationReasons(t *testing.T) {
	w, tr := recordingWorld(t)
	for _, reason := range []string{"subscription_test", "republished", "zones_changed"} {
		if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", reason, 0, "")), ContentTypeJOSE); code != http.StatusNoContent {
			t.Fatalf("%s: %d", reason, code)
		}
	}
	if tr.n() != 0 || w.count(CounterWebhookAckOnly) != 3 || w.count(CounterWebhookUnknown) != 1 {
		t.Fatalf("pulls %d ack %d unknown %d", tr.n(), w.count(CounterWebhookAckOnly), w.count(CounterWebhookUnknown))
	}
	tok := signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", 1, ""))
	if code := w.post(t, tok, ContentTypeJOSE); code != http.StatusNoContent || tr.n() != 1 {
		t.Fatalf("%d %d", code, tr.n())
	}
	if code := w.post(t, tok, ContentTypeJOSE); code != http.StatusNoContent || tr.n() != 1 || w.count(CounterWebhookReplayed) != 1 {
		t.Fatalf("replay: %d pulls %d", code, tr.n())
	}
}

// What is not a delivery is refused before anything is recorded: the
// wrong media type (415), a body over the bound (413), a payload that is
// not a cis/change/v1 record (400).
func TestNotificationMalformed(t *testing.T) {
	w, tr := recordingWorld(t)
	good := signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", 1, ""))
	if code := w.post(t, good, "application/json"); code != http.StatusUnsupportedMediaType {
		t.Fatalf("%d", code)
	}
	if code := w.post(t, strings.Repeat("a", MaxNotificationBytes+1), ContentTypeJOSE); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("%d", code)
	}
	bad := change("zones", "publication", 1, "")
	bad["dataset"] = "nothing"
	if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", bad), ContentTypeJOSE); code != http.StatusBadRequest {
		t.Fatalf("%d", code)
	}
	if tr.n() != 0 || w.count(CounterWebhookMalformed) != 3 {
		t.Fatalf("pulls %d malformed %d", tr.n(), w.count(CounterWebhookMalformed))
	}
}

// E-10: the delivery ids remembered are bounded; beyond the bound a new
// delivery is answered 503 (the CISP retries) and counted; the store
// unreachable is 503 too.
func TestNotificationDeliveryIDsAreBounded(t *testing.T) {
	w, tr := recordingWorld(t)
	w.receiver.cfg.MaxLiveJTIs = 2
	for i := range 2 {
		if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", int64(i+1), "")), ContentTypeJOSE); code != http.StatusNoContent {
			t.Fatalf("%d", code)
		}
	}
	if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", 3, "")), ContentTypeJOSE); code != http.StatusServiceUnavailable {
		t.Fatalf("%d", code)
	}
	if tr.n() != 2 || w.count(CounterWebhookJTIFull) != 1 {
		t.Fatalf("pulls %d full %d", tr.n(), w.count(CounterWebhookJTIFull))
	}
	w.cache.fail = true
	if code := w.post(t, signAs(t, w.fake.Ring, fakecisp.Issuer, "127.0.0.1", change("zones", "publication", 4, "")), ContentTypeJOSE); code != http.StatusServiceUnavailable {
		t.Fatalf("%d", code)
	}
	if w.count(CounterWebhookStoreFailed) != 1 {
		t.Fatal("not counted")
	}
}

// End to end without a database: the subscriber registers its callback
// (the CISP's subscription_test is acknowledged without a pull); a
// publication the sender delivers is notified, verified and pulled into
// the cache within seconds; with the webhooks suppressed the next one
// arrives through the reconciliation alone.
func TestWebhookThenReconciliation(t *testing.T) {
	w := newWorld(t)
	w.sub.cfg.CallbackURL = w.rx.URL + NotificationsPath
	w.sub.cfg.ReconcileInterval = 300 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { w.sub.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitFor(t, 5*time.Second, "the subscription_test acknowledged", func() bool {
		for _, d := range w.fake.Deliveries() {
			if d.Change["reason"] == "subscription_test" && d.Status == http.StatusNoContent {
				return true
			}
		}
		return false
	})
	if subs := w.fake.Subscriptions(); len(subs) != 1 || len(subs[0].Datasets) != 4 {
		t.Fatalf("%+v", subs)
	}
	w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the notified version cached", func() bool {
		c, ok := w.cache.get(DatasetZones)
		return ok && c.Version == 1
	})
	if w.count(CounterWebhooks) < 1 {
		t.Fatal("not delivered by the webhook")
	}
	w.fake.SuppressWebhooks(true)
	hooks := w.count(CounterWebhooks)
	w.enqueueZones(t, zoneFeature("TST001", "SENSITIVE"), zoneFeature("TST002", "SENSITIVE"))
	if _, err := w.sender.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "the reconciliation caught the change", func() bool {
		c, ok := w.cache.get(DatasetZones)
		return ok && c.Version == 2
	})
	if w.count(CounterWebhooks) != hooks || w.count(CounterReconcileCatchups) < 1 {
		t.Fatalf("webhooks %d, catch-ups %d", w.count(CounterWebhooks), w.count(CounterReconcileCatchups))
	}
}
