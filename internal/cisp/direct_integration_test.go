package cisp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/cisp"
)

// directANSP is the ANSP's pull_url (GET /v1/restrictions/{id}/direct)
// on its own server, reached as https://ansp.test (the ANSP's issuer and
// base URL) through the subscriber's direct client.
type directANSP struct {
	mu    sync.Mutex
	srv   *httptest.Server
	body  []byte
	sig   string
	pulls int
	creds bool
}

func newDirectANSP(t *testing.T) *directANSP {
	t.Helper()
	a := &directANSP{}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.pulls++
		a.creds = a.creds || r.Header.Get("Authorization") != ""
		if a.body == nil || !strings.HasSuffix(r.URL.Path, "/direct") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(cisp.HeaderDirectSignature, a.sig)
		_, _ = w.Write(a.body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// client dials the server for every host: https://ansp.test is this
// server, over plain http.
func (a *directANSP) client() *http.Client {
	addr := strings.TrimPrefix(a.srv.URL, "http://")
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
}

// H-2 on the real databases and NATS: the ANSP's degraded direct
// delivery lands in the authority and is applied. The CISP's
// restrictions version (2) is above the restriction's ansp_version (2
// too, then 3): the receiver used to skip it as a replay. The ANSP posts
// the activation; the authority pulls its signed restriction/direct/v1
// (no credential), stores it in cis_direct_restrictions, projects it into
// proj_restrictions for the detectors and announces cis.v1.restrictions
// (Z-12). The end goes the same way and the projection says ended.
// Absence pair: a body under another key is pulled and never projected.
func TestIntegrationDirectDeliveryProjectedAndLifted(t *testing.T) {
	ansp := newDirectANSP(t)
	s := newStack(t, false, func(su *cisp.Setup) { su.DirectClient = ansp.client() })
	announced := make(chan string, 64)
	sub, err := s.nc.Subscribe("cis.v1.restrictions", func(m *nats.Msg) { announced <- string(m.Data) })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	for i := 0; i < 2; i++ {
		f := restrictionFeature("DAR000"+strconv.Itoa(i), "active")
		if _, err := s.fake.Publish("restrictions", []json.RawMessage{f}, f, s.ansp, "restriction_activated"); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the CISP's restrictions version 2", func() bool {
		return s.one(t, s.tsAdmin, `SELECT cis_version FROM proj_restrictions_state`) == "2"
	})

	const rid, ident = "01K6P0H2D1RECT0000000000AB", "DARH2D1"
	now := time.Now().UTC().Truncate(time.Millisecond)
	feature := fmt.Sprintf(`{"type":"Feature","geometry":{"type":"Polygon","coordinates":[[[44.80,41.70],[44.82,41.70],[44.82,41.72],[44.80,41.72],[44.80,41.70]]],"layer":{"lower":0,"lowerReference":"AGL","upper":120,"upperReference":"AGL","uom":"m"}},"properties":{"identifier":%q,"country":"GEO","type":"PROHIBITED","variant":"COMMON","reason":["DAR"],"limitedApplicability":[{"startDateTime":%q,"endDateTime":%q}],"zoneAuthority":[{"name":[{"text":"Test ANSP","lang":"en-GB"}],"purpose":"NOTIFICATION"}]}}`,
		ident, now.Format(time.RFC3339Nano), now.Add(3*time.Hour).Format(time.RFC3339Nano))
	serve := func(version int64, state string, ring *auth.KeyRing) {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"schema": cisp.DirectSchema, "id": rid, "ansp_ref": "ansp-01:" + rid, "ansp_version": version, "identifier": ident,
			"uspace_airspace_id": "TSU001", "state": state, "starts_at": now, "ends_at": now.Add(3 * time.Hour), "changed_at": time.Now().UTC(),
			"feature": json.RawMessage(feature),
		})
		if err != nil {
			t.Fatal(err)
		}
		sig, err := ring.SignDetached(body, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		ansp.mu.Lock()
		ansp.body, ansp.sig = body, sig
		ansp.mu.Unlock()
	}
	notify := func(version int64, reason string) {
		t.Helper()
		b, err := json.Marshal(map[string]any{
			"schema": "cis/change/v1", "msg_id": "01K6P0H2D1JT1" + strconv.FormatInt(time.Now().UnixNano()%1e13, 10), "producer": "ansp/api",
			"dataset": "restrictions", "version": version, "etag": `"ansp-01:` + rid + `:` + strconv.FormatInt(version, 10) + `"`,
			"feature_ids": []string{ident}, "removed_ids": []string{}, "reason": reason, "at": time.Now().UTC(),
			"pull_url": "https://ansp.test/v1/restrictions/" + rid + "/direct",
		})
		if err != nil {
			t.Fatal(err)
		}
		tok, err := s.ansp.SignCompact(auth.CompactClaims{Issuer: "https://ansp.test", Audience: "127.0.0.1", Subject: rid,
			JTI: "jti-" + strconv.FormatInt(time.Now().UnixNano(), 10)}, b, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, s.callback, strings.NewReader(tok))
		req.Header.Set("Content-Type", cisp.ContentTypeJOSE)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("notify %s: %d", reason, resp.StatusCode)
		}
	}
	state := func() string {
		return s.one(t, s.tsAdmin, `SELECT state FROM proj_restrictions WHERE identifier = $1`, ident)
	}

	// The absence: another key's body is pulled and refused.
	serve(2, "active", newRing(t, "not-the-ansp"))
	notify(2, "restriction_activated")
	waitFor(t, "the refused pull", func() bool { return s.parts.Counters.Get(cisp.CounterDirectRefused) >= 1 })
	if st := state(); st != "" {
		t.Fatalf("a body the ANSP did not sign was projected %q", st)
	}
	// The presence.
	serve(2, "active", s.ansp)
	notify(2, "restriction_activated")
	waitFor(t, "the direct restriction projected active", func() bool { return state() == "active" })
	if v := s.one(t, s.tsAdmin, `SELECT cis_version FROM proj_restrictions_state`); v != "2" {
		t.Fatalf("the projection's CIS version moved: %s", v)
	}
	if n := s.one(t, s.pgAdmin, `SELECT count(*) FROM cis_direct_restrictions WHERE identifier = $1 AND ansp_version = 2 AND state = 'active'`, ident); n != "1" {
		t.Fatalf("stored %s", n)
	}
	if st := s.one(t, s.tsAdmin, `SELECT state FROM proj_restrictions WHERE identifier = 'DAR0001'`); st != "active" {
		t.Fatalf("the CISP's restriction is gone from the projection: %q", st)
	}
	waitFor(t, "cis.v1.restrictions announced", func() bool {
		select {
		case <-announced:
			return true
		default:
			return false
		}
	})
	ansp.mu.Lock()
	creds := ansp.creds
	ansp.mu.Unlock()
	if creds {
		t.Fatal("a credential was sent to the ANSP's pull_url")
	}
	// The lift, still without the CISP.
	serve(3, "ended", s.ansp)
	notify(3, "restriction_ended")
	waitFor(t, "the direct restriction projected ended", func() bool { return state() == "ended" })
	if n := s.one(t, s.pgAdmin, `SELECT ansp_version FROM cis_direct_restrictions WHERE identifier = $1`, ident); n != "3" {
		t.Fatalf("stored version %s", n)
	}
}
