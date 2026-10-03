// Package fakecisp is a fake CISP for tests (WP-6): an HTTPS server
// implementing exactly the parts of the CISP's contract (the pinned
// api/clients/cisp.yaml; spec 02 F1, F3) the authority calls, plus the
// publisher heartbeat:
//
//   - PUT /v1/publications/{dataset}: bearer required, the detached JWS
//     of X-JWS-Signature verified with core's DetachedVerifier against
//     the authority's keys (403 signature), If-Match absent 428, another
//     version 412 with the current ETag, equal bytes 200 unchanged, else
//     201 and a new version; then every subscription is notified;
//   - GET /v1/publications/{dataset}: the versions, newest first, with
//     body_sha256;
//   - POST /v1/publishers/heartbeat: recorded on the fake's clock; a
//     publisher silent for StaleAfter (60 s) is stale;
//   - GET, POST, PATCH /v1/subscriptions: registration; a new
//     subscription is sent a subscription_test;
//   - GET and HEAD /v1/{dataset} with If-None-Match and since_version (a
//     DatasetDelta); 404 no_version before the first version;
//   - GET /v1/{dataset}/versions/{v}: the publisher's bytes with
//     X-Publisher-Signature and X-Publisher-Kid.
//
// Notifications are compact JWS (core's KeyRing.SignCompact) of a
// cis/change/v1 record, aud the callback's host. Controls make the CISP
// go down, suppress its webhooks, answer PUTs with a forced status, and
// publish versions as another publisher (the ANSP's restrictions, or a
// conflicting zones version). It is imported by tests only (plan §3).
package fakecisp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/auth"
)

// Issuer is the fake's iss in notifications.
const Issuer = "https://cisp.test"

// StaleAfter is the publisher staleness of the CISP (three missed 15 s
// heartbeats).
const StaleAfter = 60 * time.Second

// Version is one stored version.
type Version struct {
	Number int64
	// Served is the dataset as GET /v1/{dataset} serves it.
	Served []byte
	// Published is the publisher's bytes and their detached JWS.
	Published    []byte
	Signature    string
	SignatureKID string
	Features     map[string]json.RawMessage
	Order        []string
	USSPs        bool
}

// Request is one request the fake received.
type Request struct {
	Method string
	Path   string
	Scope  string
	Query  string
}

// Delivery is one notification the fake sent.
type Delivery struct {
	Callback string
	Change   map[string]any
	Status   int
	Err      string
}

// Subscription is one registered subscription.
type Subscription struct {
	ID       string
	Callback string
	Datasets []string
	BBox     []float64
}

// Fake is the fake CISP.
type Fake struct {
	Server *httptest.Server
	Ring   *auth.KeyRing

	verifier *auth.DetachedVerifier

	mu            sync.Mutex
	now           func() time.Time
	versions      map[string][]*Version
	requests      []Request
	deliveries    []Delivery
	subs          []*Subscription
	subsMade      int
	heartbeats    []time.Time
	down          bool
	suppress      bool
	putStatus     []int
	cursor        int64
	callbackHTTP  *http.Client
	lastHeartbeat time.Time
}

// New starts a fake CISP that accepts publications signed by the keys of
// authorityKeys (the authority's publication JWKS). now is its clock
// (nil: time.Now); callbacks are posted with callbackClient (nil: a
// plain client).
func New(authorityKeys auth.IssuerConfig, now func() time.Time, callbackClient *http.Client) (*Fake, error) {
	if now == nil {
		now = time.Now
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	ring, err := auth.NewKeyRing(auth.SigningKey{KID: "fake-cisp-1", Key: key})
	if err != nil {
		return nil, err
	}
	v, err := auth.NewDetachedVerifier(context.Background(), auth.DetachedConfig{
		Publishers: map[string]auth.IssuerConfig{"authority": authorityKeys}, Now: now,
	})
	if err != nil {
		return nil, err
	}
	if callbackClient == nil {
		callbackClient = &http.Client{Timeout: 2 * time.Second}
	}
	f := &Fake{Ring: ring, verifier: v, now: now, versions: map[string][]*Version{}, callbackHTTP: callbackClient}
	f.Server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	return f, nil
}

// Close stops the server.
func (f *Fake) Close() { f.Server.Close() }

// URL is the fake's base URL (https).
func (f *Fake) URL() string { return f.Server.URL }

// Client trusts the fake's certificate.
func (f *Fake) Client() *http.Client { return f.Server.Client() }

// SetDown makes every request answer 503 (true) or not.
func (f *Fake) SetDown(down bool) {
	f.mu.Lock()
	f.down = down
	f.mu.Unlock()
}

// SuppressWebhooks stops (true) or resumes notifications.
func (f *Fake) SuppressWebhooks(on bool) {
	f.mu.Lock()
	f.suppress = on
	f.mu.Unlock()
}

// FailPuts answers the next len(statuses) PUTs with these statuses.
func (f *Fake) FailPuts(statuses ...int) {
	f.mu.Lock()
	f.putStatus = append(f.putStatus, statuses...)
	f.mu.Unlock()
}

// Requests are the requests received so far.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.requests)
}

// Deliveries are the notifications sent so far.
func (f *Fake) Deliveries() []Delivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.deliveries)
}

// DropSubscriptions forgets every subscription, as a CISP restored from
// a backup or an operator's delete would.
func (f *Fake) DropSubscriptions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = nil
}

// Subscriptions are the registered subscriptions.
func (f *Fake) Subscriptions() []Subscription {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Subscription, 0, len(f.subs))
	for _, s := range f.subs {
		out = append(out, *s)
	}
	return out
}

// Heartbeats are the arrival times of the heartbeats, on the fake's clock.
func (f *Fake) Heartbeats() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.heartbeats)
}

// PublisherStale is the CISP's judgement of the authority at now: stale
// when its last heartbeat is older than StaleAfter or it never sent one.
func (f *Fake) PublisherStale(now time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastHeartbeat.IsZero() || now.Sub(f.lastHeartbeat) > StaleAfter
}

// Current is the current version of ds, or nil.
func (f *Fake) Current(ds string) *Version {
	f.mu.Lock()
	defer f.mu.Unlock()
	vs := f.versions[ds]
	if len(vs) == 0 {
		return nil
	}
	return vs[len(vs)-1]
}

// Publish stores a new version of ds as another publisher would have
// published it: features (each an ED-318 feature, with a restriction's
// cis_restriction already in it), the publisher's bytes and their
// signature by ring (nil: unsigned, a version the CISP made). It
// notifies the subscriptions with reason.
func (f *Fake) Publish(ds string, features []json.RawMessage, published []byte, ring *auth.KeyRing, reason string) (*Version, error) {
	v := &Version{Published: published, Features: map[string]json.RawMessage{}}
	for _, ft := range features {
		id, err := identifier(ft)
		if err != nil {
			return nil, err
		}
		v.Features[id] = ft
		v.Order = append(v.Order, id)
	}
	if ring != nil {
		sig, err := ring.SignDetached(published, f.now())
		if err != nil {
			return nil, err
		}
		v.Signature, v.SignatureKID = sig, ring.ActiveKID()
	}
	f.mu.Lock()
	prev := f.currentLocked(ds)
	f.storeLocked(ds, v)
	f.mu.Unlock()
	f.notify(ds, v, prev, reason)
	return v, nil
}

func identifier(ft json.RawMessage) (string, error) {
	var x struct {
		Properties struct {
			Identifier string `json:"identifier"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(ft, &x); err != nil || x.Properties.Identifier == "" {
		return "", fmt.Errorf("a feature without properties.identifier")
	}
	return x.Properties.Identifier, nil
}

func (f *Fake) currentLocked(ds string) *Version {
	vs := f.versions[ds]
	if len(vs) == 0 {
		return nil
	}
	return vs[len(vs)-1]
}

// storeLocked numbers v and builds its served body.
func (f *Fake) storeLocked(ds string, v *Version) {
	v.Number = int64(len(f.versions[ds]) + 1)
	if v.USSPs {
		var m map[string]json.RawMessage
		_ = json.Unmarshal(v.Published, &m)
		m["cis_dataset"], _ = json.Marshal(ds)
		m["cis_version"], _ = json.Marshal(v.Number)
		m["cis_updated_at"], _ = json.Marshal(f.now().UTC())
		v.Served, _ = json.Marshal(m)
	} else {
		feats := make([]json.RawMessage, 0, len(v.Order))
		for _, id := range v.Order {
			feats = append(feats, v.Features[id])
		}
		v.Served, _ = json.Marshal(map[string]any{
			"type": "FeatureCollection", "features": feats, "metadata": map[string]any{"issued": f.now().UTC()},
			"cis_dataset": ds, "cis_version": v.Number, "cis_updated_at": f.now().UTC(),
		})
	}
	f.versions[ds] = append(f.versions[ds], v)
}

func etag(ds string, v int64) string { return `"` + ds + ":" + strconv.FormatInt(v, 10) + `"` }

func problem(w http.ResponseWriter, status int, slug, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "https://schemas.uspace.ge/problems/" + slug, "title": http.StatusText(status), "status": status,
		"detail": detail, "errors": []any{},
	})
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	scope := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	f.requests = append(f.requests, Request{Method: r.Method, Path: r.URL.Path, Scope: scope, Query: r.URL.RawQuery})
	down := f.down
	f.mu.Unlock()
	if down {
		problem(w, http.StatusServiceUnavailable, "unavailable", "the fake CISP is down")
		return
	}
	if scope == "" {
		problem(w, http.StatusUnauthorized, "unauthenticated", "no bearer")
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	switch {
	case r.URL.Path == "/v1/publishers/heartbeat" && r.Method == http.MethodPost:
		f.heartbeat(w, r)
	case len(parts) == 2 && parts[0] == "publications" && r.Method == http.MethodPut:
		f.put(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "publications" && r.Method == http.MethodGet:
		f.list(w, parts[1])
	case parts[0] == "subscriptions":
		f.subscriptions(w, r, parts)
	case len(parts) == 1 && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		f.dataset(w, r, parts[0])
	case len(parts) == 3 && parts[1] == "versions" && r.Method == http.MethodGet:
		f.version(w, parts[0], parts[2])
	default:
		problem(w, http.StatusNotFound, "not_found", "no such route in the fake CISP")
	}
}

func (f *Fake) heartbeat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SentAt *time.Time `json:"sent_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.SentAt == nil {
		problem(w, http.StatusBadRequest, "validation", "sent_at is required")
		return
	}
	f.mu.Lock()
	at := f.now()
	f.heartbeats = append(f.heartbeats, at)
	f.lastHeartbeat = at
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *Fake) put(w http.ResponseWriter, r *http.Request, ds string) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if _, err := f.verifier.Verify(r.Context(), "authority", r.Header.Get("X-JWS-Signature"), body); err != nil {
		problem(w, http.StatusForbidden, "signature", err.Error())
		return
	}
	f.mu.Lock()
	if len(f.putStatus) > 0 {
		st := f.putStatus[0]
		f.putStatus = f.putStatus[1:]
		f.mu.Unlock()
		problem(w, st, "forced", "a status forced by the test")
		return
	}
	cur := f.currentLocked(ds)
	var n int64
	if cur != nil {
		n = cur.Number
	}
	ifMatch := r.Header.Get("If-Match")
	switch {
	case ifMatch == "":
		f.mu.Unlock()
		problem(w, http.StatusPreconditionRequired, "precondition_required", "If-Match is required")
		return
	case strings.TrimSpace(ifMatch) != etag(ds, n):
		f.mu.Unlock()
		w.Header().Set("ETag", etag(ds, n))
		problem(w, http.StatusPreconditionFailed, "precondition_failed", "If-Match names "+ifMatch)
		return
	case cur != nil && bytes.Equal(cur.Published, body):
		f.mu.Unlock()
		w.Header().Set("ETag", etag(ds, n))
		writeJSON(w, http.StatusOK, map[string]any{"dataset": ds, "version": n, "etag": etag(ds, n), "unchanged": true})
		return
	}
	v := &Version{Published: body, Signature: r.Header.Get("X-JWS-Signature"), Features: map[string]json.RawMessage{}}
	if ds == "ussp_list" {
		v.USSPs = true
	} else {
		var fc struct {
			Features []json.RawMessage `json:"features"`
		}
		if err := json.Unmarshal(body, &fc); err != nil {
			f.mu.Unlock()
			problem(w, http.StatusBadRequest, "publication_refused", "not a FeatureCollection")
			return
		}
		for _, ft := range fc.Features {
			id, err := identifier(ft)
			if err != nil {
				f.mu.Unlock()
				problem(w, http.StatusBadRequest, "publication_refused", err.Error())
				return
			}
			v.Features[id] = ft
			v.Order = append(v.Order, id)
		}
	}
	if h, err := auth.ParseDetachedHeader(v.Signature); err == nil {
		v.SignatureKID = h.KID
	}
	f.storeLocked(ds, v)
	f.mu.Unlock()
	w.Header().Set("ETag", etag(ds, v.Number))
	writeJSON(w, http.StatusCreated, map[string]any{"dataset": ds, "version": v.Number, "etag": etag(ds, v.Number)})
	f.notify(ds, v, cur, "publication")
}

func (f *Fake) list(w http.ResponseWriter, ds string) {
	f.mu.Lock()
	vs := slices.Clone(f.versions[ds])
	f.mu.Unlock()
	out := []map[string]any{}
	for i := len(vs) - 1; i >= 0; i-- {
		v := vs[i]
		sum := sha256.Sum256(v.Published)
		out = append(out, map[string]any{
			"dataset": ds, "version": v.Number, "etag": etag(ds, v.Number), "publisher": "authority-01",
			"received_at": f.now().UTC(), "feature_count": len(v.Order), "added": 0, "changed": 0, "removed": 0,
			"reason": "publication", "warnings": []any{}, "body_sha256": hex.EncodeToString(sum[:]),
			"bytes": len(v.Published), "content_type": "application/json",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"dataset": ds, "versions": out})
}

func (f *Fake) dataset(w http.ResponseWriter, r *http.Request, ds string) {
	cur := f.Current(ds)
	if cur == nil {
		problem(w, http.StatusNotFound, "no_version", "the dataset has no version yet")
		return
	}
	w.Header().Set("ETag", etag(ds, cur.Number))
	w.Header().Set("X-CIS-Version", strconv.FormatInt(cur.Number, 10))
	if r.Header.Get("If-None-Match") == etag(ds, cur.Number) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	if sv := r.URL.Query().Get("since_version"); sv != "" {
		from, err := strconv.ParseInt(sv, 10, 64)
		if err != nil || from > cur.Number {
			problem(w, http.StatusBadRequest, "validation", "since_version")
			return
		}
		writeJSON(w, http.StatusOK, f.delta(ds, from, cur))
		return
	}
	w.Header().Set("Content-Type", "application/geo+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(cur.Served)
}

// delta is the DatasetDelta from version from to cur.
func (f *Fake) delta(ds string, from int64, cur *Version) map[string]any {
	f.mu.Lock()
	var old *Version
	if from > 0 && int(from) <= len(f.versions[ds]) {
		old = f.versions[ds][from-1]
	}
	f.mu.Unlock()
	added, changed, removed := []json.RawMessage{}, []json.RawMessage{}, []string{}
	for _, id := range cur.Order {
		ft := cur.Features[id]
		switch {
		case old == nil || old.Features[id] == nil:
			added = append(added, ft)
		case !bytes.Equal(old.Features[id], ft):
			changed = append(changed, ft)
		}
	}
	if old != nil {
		for _, id := range old.Order {
			if cur.Features[id] == nil {
				removed = append(removed, id)
			}
		}
	}
	return map[string]any{
		"dataset": ds, "from_version": from, "to_version": cur.Number,
		"added":   map[string]any{"type": "FeatureCollection", "features": added},
		"changed": map[string]any{"type": "FeatureCollection", "features": changed},
		"removed": removed,
	}
}

func (f *Fake) version(w http.ResponseWriter, ds, raw string) {
	n, err := strconv.ParseInt(raw, 10, 64)
	f.mu.Lock()
	vs := f.versions[ds]
	var v *Version
	if err == nil && n >= 1 && int(n) <= len(vs) {
		v = vs[n-1]
	}
	f.mu.Unlock()
	if v == nil {
		problem(w, http.StatusNotFound, "not_found", "no such version")
		return
	}
	w.Header().Set("ETag", etag(ds, v.Number))
	w.Header().Set("X-CIS-Version", strconv.FormatInt(v.Number, 10))
	w.Header().Set("X-CIS-Signature", "unused-by-the-fake")
	if v.Signature != "" {
		w.Header().Set("X-Publisher-Signature", v.Signature)
		w.Header().Set("X-Publisher-Kid", v.SignatureKID)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(v.Published)
}

func (f *Fake) subscriptions(w http.ResponseWriter, r *http.Request, parts []string) {
	switch {
	case len(parts) == 1 && r.Method == http.MethodGet:
		f.mu.Lock()
		out := make([]map[string]any, 0, len(f.subs))
		for _, s := range f.subs {
			out = append(out, subJSON(s))
		}
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
	case len(parts) == 1 && r.Method == http.MethodPost:
		var in struct {
			CallbackURL string    `json:"callback_url"`
			Datasets    []string  `json:"datasets"`
			BBox        []float64 `json:"bbox"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.CallbackURL == "" || len(in.Datasets) == 0 {
			problem(w, http.StatusBadRequest, "validation", "callback_url and datasets are required")
			return
		}
		f.mu.Lock()
		f.subsMade++
		s := &Subscription{ID: fmt.Sprintf("sub-%d", f.subsMade), Callback: in.CallbackURL, Datasets: in.Datasets, BBox: in.BBox}
		f.subs = append(f.subs, s)
		f.mu.Unlock()
		w.Header().Set("Location", "/v1/subscriptions/"+s.ID)
		writeJSON(w, http.StatusCreated, subJSON(s))
		go f.deliver(s, map[string]any{
			"schema": "cis/change/v1", "msg_id": newULID(), "producer": "cisp/deliver-fake", "dataset": s.Datasets[0],
			"version": 0, "etag": etag(s.Datasets[0], 0), "feature_ids": []string{}, "removed_ids": []string{},
			"reason": "subscription_test", "at": f.now().UTC(), "pull_url": f.URL() + "/v1/" + s.Datasets[0],
		})
	case len(parts) == 2 && r.Method == http.MethodPatch:
		var in struct {
			Datasets []string  `json:"datasets"`
			BBox     []float64 `json:"bbox"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		f.mu.Lock()
		var s *Subscription
		for _, x := range f.subs {
			if x.ID == parts[1] {
				s = x
			}
		}
		if s != nil {
			s.Datasets, s.BBox = in.Datasets, in.BBox
		}
		f.mu.Unlock()
		if s == nil {
			problem(w, http.StatusNotFound, "not_found", "no such subscription")
			return
		}
		writeJSON(w, http.StatusOK, subJSON(s))
	default:
		problem(w, http.StatusNotFound, "not_found", "no such route in the fake CISP")
	}
}

func subJSON(s *Subscription) map[string]any {
	m := map[string]any{
		"id": s.ID, "client_id": "authority-01", "callback_url": s.Callback, "datasets": s.Datasets, "status": "active",
		"created_at": time.Now().UTC(), "consecutive_failures": 0,
	}
	if s.BBox != nil {
		m["bbox"] = s.BBox
	}
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// notify sends every subscription of ds the change from prev to v,
// unless suppressed.
func (f *Fake) notify(ds string, v, prev *Version, reason string) {
	f.mu.Lock()
	if f.suppress {
		f.mu.Unlock()
		return
	}
	f.cursor++
	cursor := f.cursor
	subs := slices.Clone(f.subs)
	f.mu.Unlock()
	var from int64
	ids := []string{}
	removed := []string{}
	if prev != nil {
		from = prev.Number
		for _, id := range prev.Order {
			if v.Features[id] == nil {
				removed = append(removed, id)
			}
		}
	}
	for _, id := range v.Order {
		if prev == nil || !bytes.Equal(prev.Features[id], v.Features[id]) {
			ids = append(ids, id)
		}
	}
	ids = append(ids, removed...)
	slices.Sort(ids)
	change := map[string]any{
		"schema": "cis/change/v1", "msg_id": strconv.FormatInt(cursor, 10), "producer": "cisp/deliver-fake", "dataset": ds,
		"version": v.Number, "etag": etag(ds, v.Number), "feature_ids": ids, "removed_ids": removed, "reason": reason,
		"at": f.now().UTC(), "pull_url": f.URL() + "/v1/" + ds + "?since_version=" + strconv.FormatInt(from, 10),
	}
	for _, s := range subs {
		if slices.Contains(s.Datasets, ds) {
			f.deliver(s, change)
		}
	}
}

// Notify sends change (a cis/change/v1 record) to every subscription
// as the CISP would, signed by the fake's ring, and returns the
// receiver's status.
func (f *Fake) Notify(change map[string]any) []Delivery {
	f.mu.Lock()
	subs := slices.Clone(f.subs)
	f.mu.Unlock()
	out := make([]Delivery, 0, len(subs))
	for _, s := range subs {
		out = append(out, f.deliver(s, change))
	}
	return out
}

func (f *Fake) deliver(s *Subscription, change map[string]any) Delivery {
	d := Delivery{Callback: s.Callback, Change: change}
	body, err := json.Marshal(change)
	if err == nil {
		var tok string
		tok, err = f.Sign(s.Callback, s.ID, body)
		if err == nil {
			var req *http.Request
			req, err = http.NewRequest(http.MethodPost, s.Callback, strings.NewReader(tok))
			if err == nil {
				req.Header.Set("Content-Type", "application/jose")
				var resp *http.Response
				resp, err = f.callbackHTTP.Do(req)
				if err == nil {
					d.Status = resp.StatusCode
					_ = resp.Body.Close()
				}
			}
		}
	}
	if err != nil {
		d.Err = err.Error()
	}
	f.mu.Lock()
	f.deliveries = append(f.deliveries, d)
	f.mu.Unlock()
	return d
}

// Sign is the compact JWS of a delivery of body to callback (aud the
// callback's host without its port, sub the subscription, a fresh jti).
func (f *Fake) Sign(callback, sub string, body []byte) (string, error) {
	u, err := url.Parse(callback)
	if err != nil {
		return "", err
	}
	return f.Ring.SignCompact(auth.CompactClaims{Issuer: Issuer, Audience: u.Hostname(), Subject: sub, JTI: newULID()},
		body, f.now())
}

// newULID is a fresh delivery id (26 Crockford base32 characters).
func newULID() string {
	const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [26]byte
	var r [26]byte
	_, _ = rand.Read(r[:])
	for i := range b {
		b[i] = crockford[int(r[i])%32]
	}
	return string(b[:])
}
