// Package fakedss is a fake InterUSS DSS and a fake F3411 Service
// Provider for the Display Provider's tests (WP-14), served through the
// server generated from the pinned F3411 contract
// (internal/dp/ridapi, api/clients/dss-rid.yaml) with uspace-core's
// types, so every member on the wire is the standard's. The DSS keeps
// ISAs and subscriptions in memory and answers the searches; the
// Service Provider serves flights and details and posts ISA changes to
// the subscribers the DSS lists, as F3411 has the owner of an ISA do.
// The DSS also answers F3548 USS availability (GET and PUT
// /dss/v1/uss_availability/{uss_id}). Faults are switches: the DSS or
// the Service Provider down, a 413, a delay. Every bearer token is
// recorded (its claims read unverified) so a test can check the aud and
// the scope a call carried. Test-only (internal/ltest).
package fakedss

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/f3411"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dp/ridapi"
)

// Claims are the claims a call's bearer token carried (read unverified).
type Claims struct {
	Path  string
	Aud   string
	Scope string
	Sub   string
}

type sub struct {
	id, version, base string
	box               dp.Box
	start, end        time.Time
}

// DSS is the fake DSS.
type DSS struct {
	srv *httptest.Server

	mu           sync.Mutex
	isas         map[string]isaEntry
	subs         map[string]*sub
	down         bool
	searches     int
	subPuts      int
	subDeletes   int
	claims       []Claims
	availability map[string]f3548.UssAvailabilityStatusResponse
}

type isaEntry struct {
	isa f3411.IdentificationServiceArea
	box dp.Box
}

// SP is the fake Service Provider.
type SP struct {
	srv *httptest.Server

	mu       sync.Mutex
	flights  []f3411.RIDFlight
	details  map[string]f3411.RIDFlightDetails
	respTS   func() time.Time
	down     bool
	status   int
	delay    time.Duration
	polls    int
	detailsN int
	claims   []Claims
	views    []string
}

// NewDSS starts the fake DSS; its URL is the DSS base URL (F3411 under
// /rid/v2).
func NewDSS() *DSS {
	d := &DSS{isas: map[string]isaEntry{}, subs: map[string]*sub{}, availability: map[string]f3548.UssAvailabilityStatusResponse{}}
	mux := http.NewServeMux()
	ridapi.HandlerWithOptions(dssServer{d}, ridapi.StdHTTPServerOptions{BaseURL: "/rid/v2", BaseRouter: mux})
	mux.HandleFunc("GET /dss/v1/uss_availability/{uss_id}", d.getAvailability)
	mux.HandleFunc("PUT /dss/v1/uss_availability/{uss_id}", d.putAvailability)
	d.srv = httptest.NewServer(d.gate(mux))
	return d
}

// NewSP starts the fake Service Provider; its URL is its uss_base_url.
func NewSP() *SP {
	s := &SP{details: map[string]f3411.RIDFlightDetails{}, respTS: time.Now}
	mux := http.NewServeMux()
	ridapi.HandlerWithOptions(spServer{s}, ridapi.StdHTTPServerOptions{BaseRouter: mux})
	s.srv = httptest.NewServer(mux)
	return s
}

// URL is the DSS base URL.
func (d *DSS) URL() string { return d.srv.URL }

// URL is the Service Provider's uss_base_url.
func (s *SP) URL() string { return s.srv.URL }

// Close stops the server.
func (d *DSS) Close() { d.srv.Close() }

// Close stops the server.
func (s *SP) Close() { s.srv.Close() }

func readClaims(r *http.Request) Claims {
	c := Claims{Path: r.Method + " " + r.URL.Path}
	tok := dp.Bearer(r)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return c
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c
	}
	var cl struct {
		Aud   any    `json:"aud"`
		Scope string `json:"scope"`
		Sub   string `json:"sub"`
	}
	if json.Unmarshal(raw, &cl) == nil {
		switch a := cl.Aud.(type) {
		case string:
			c.Aud = a
		case []any:
			if len(a) > 0 {
				c.Aud, _ = a[0].(string)
			}
		}
		c.Scope, c.Sub = cl.Scope, cl.Sub
	}
	return c
}

func (d *DSS) gate(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		down := d.down
		d.claims = append(d.claims, readClaims(r))
		d.mu.Unlock()
		if down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// SetDown makes the DSS answer 503 to everything.
func (d *DSS) SetDown(down bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.down = down
}

// Counts are the searches, subscription writes and deletes made.
func (d *DSS) Counts() (searches, subPuts, subDeletes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.searches, d.subPuts, d.subDeletes
}

// Claims are the claims of every call so far.
func (d *DSS) Claims() []Claims {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Claims(nil), d.claims...)
}

// Subscriptions lists the live subscriptions' ids, versions, ends and
// uss_base_urls.
func (d *DSS) Subscriptions() map[string][3]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := map[string][3]string{}
	for id, s := range d.subs {
		out[id] = [3]string{s.version, s.end.UTC().Format(time.RFC3339Nano), s.base}
	}
	return out
}

// DropSubscriptions forgets every subscription, as a DSS that lost them
// would: a renewal with the held version is then refused.
func (d *DSS) DropSubscriptions() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.subs = map[string]*sub{}
}

// PutISA stores an ISA over box, owned by owner, for spURL, from start
// to end; the subscribers whose area meets it are returned, as F3411's
// PutIdentificationServiceAreaResponse lists them.
func (d *DSS) PutISA(id, owner, spURL string, box dp.Box, start, end time.Time) []f3411.SubscriberToNotify {
	d.mu.Lock()
	defer d.mu.Unlock()
	v := strconv.FormatInt(time.Now().UnixNano(), 10)
	isa := f3411.IdentificationServiceArea{Id: id, Owner: owner, UssBaseUrl: spURL, Version: v,
		TimeStart: f3411.Time{Format: f3411.RFC3339, Value: start.UTC()}, TimeEnd: f3411.Time{Format: f3411.RFC3339, Value: end.UTC()}}
	d.isas[id] = isaEntry{isa: isa, box: box}
	return d.subscribersLocked(box)
}

// DeleteISA removes an ISA and returns its subscribers.
func (d *DSS) DeleteISA(id string) []f3411.SubscriberToNotify {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.isas[id]
	if !ok {
		return nil
	}
	delete(d.isas, id)
	return d.subscribersLocked(e.box)
}

func (d *DSS) subscribersLocked(box dp.Box) []f3411.SubscriberToNotify {
	by := map[string][]f3411.SubscriptionState{}
	for _, s := range d.subs {
		if dp.Intersects(s.box, box) {
			by[s.base] = append(by[s.base], f3411.SubscriptionState{SubscriptionId: s.id})
		}
	}
	out := make([]f3411.SubscriberToNotify, 0, len(by))
	for base, states := range by {
		out = append(out, f3411.SubscriberToNotify{Url: base, Subscriptions: states})
	}
	return out
}

// ISA is the stored ISA id.
func (d *DSS) ISA(id string) (f3411.IdentificationServiceArea, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.isas[id]
	return e.isa, ok
}

// Availability is the availability the DSS holds for a USS.
func (d *DSS) Availability(uss string) (f3548.UssAvailabilityStatusResponse, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.availability[uss]
	return a, ok
}

type dssServer struct{ d *DSS }

func parseArea(s string) (dp.Box, error) {
	parts := strings.Split(s, ",")
	if len(parts) < 6 || len(parts)%2 != 0 {
		return dp.Box{}, fmt.Errorf("area %q", s)
	}
	b := dp.Box{MinLat: 90, MinLon: 180, MaxLat: -90, MaxLon: -180}
	for i := 0; i < len(parts); i += 2 {
		lat, err1 := strconv.ParseFloat(parts[i], 64)
		lng, err2 := strconv.ParseFloat(parts[i+1], 64)
		if err1 != nil || err2 != nil {
			return dp.Box{}, fmt.Errorf("area %q", s)
		}
		b.MinLat, b.MaxLat = min(b.MinLat, lat), max(b.MaxLat, lat)
		b.MinLon, b.MaxLon = min(b.MinLon, lng), max(b.MaxLon, lng)
	}
	return b, nil
}

func msg(s string) f3411.ErrorResponse { return f3411.ErrorResponse{Message: &s} }

// SearchIdentificationServiceAreas implements ridapi.ServerInterface.
func (s dssServer) SearchIdentificationServiceAreas(w http.ResponseWriter, _ *http.Request, p f3411.SearchIdentificationServiceAreasParams) {
	box, err := parseArea(p.Area)
	if err != nil {
		writeJSON(w, 400, msg(err.Error()))
		return
	}
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	s.d.searches++
	out := []f3411.IdentificationServiceArea{}
	for id := range s.d.isas {
		if e := s.d.isas[id]; dp.Intersects(e.box, box) {
			out = append(out, e.isa)
		}
	}
	writeJSON(w, 200, f3411.SearchIdentificationServiceAreasResponse{ServiceAreas: &out})
}

func (s dssServer) putSub(w http.ResponseWriter, r *http.Request, id, version string) {
	var body f3411.CreateSubscriptionParameters
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, msg("body"))
		return
	}
	box, _, end, err := f3411.Volume4DToZonesEnvelope(body.Extents)
	if err != nil {
		writeJSON(w, 400, msg(err.Error()))
		return
	}
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	cur, exists := s.d.subs[id]
	switch {
	case version == "" && exists:
		writeJSON(w, 409, msg("exists"))
		return
	case version != "" && (!exists || cur.version != version):
		writeJSON(w, 409, msg("version"))
		return
	}
	s.d.subPuts++
	start := time.Now().UTC()
	if body.Extents.TimeStart != nil {
		start = body.Extents.TimeStart.Value
	}
	sb := &sub{id: id, version: strconv.FormatInt(time.Now().UnixNano(), 10), base: body.UssBaseUrl, box: box, start: start, end: end}
	s.d.subs[id] = sb
	var areas []f3411.IdentificationServiceArea
	for id := range s.d.isas {
		if e := s.d.isas[id]; dp.Intersects(e.box, box) {
			areas = append(areas, e.isa)
		}
	}
	ts, te := f3411.Time{Format: f3411.RFC3339, Value: sb.start}, f3411.Time{Format: f3411.RFC3339, Value: sb.end}
	writeJSON(w, 200, f3411.PutSubscriptionResponse{ServiceAreas: &areas, Subscription: f3411.Subscription{
		Id: id, Owner: "authority-01", UssBaseUrl: sb.base, Version: sb.version, TimeStart: &ts, TimeEnd: &te}})
}

// CreateSubscription implements ridapi.ServerInterface.
func (s dssServer) CreateSubscription(w http.ResponseWriter, r *http.Request, id string) {
	s.putSub(w, r, id, "")
}

// UpdateSubscription implements ridapi.ServerInterface.
func (s dssServer) UpdateSubscription(w http.ResponseWriter, r *http.Request, id, version string) {
	s.putSub(w, r, id, version)
}

// DeleteSubscription implements ridapi.ServerInterface.
func (s dssServer) DeleteSubscription(w http.ResponseWriter, _ *http.Request, id, version string) {
	s.d.mu.Lock()
	defer s.d.mu.Unlock()
	cur, ok := s.d.subs[id]
	if !ok || cur.version != version {
		writeJSON(w, 404, msg("no such subscription"))
		return
	}
	delete(s.d.subs, id)
	s.d.subDeletes++
	writeJSON(w, 200, f3411.DeleteSubscriptionResponse{Subscription: f3411.Subscription{Id: id, Owner: "authority-01", UssBaseUrl: cur.base, Version: cur.version}})
}

// SearchFlights is the SP's.
func (s dssServer) SearchFlights(w http.ResponseWriter, _ *http.Request, _ f3411.SearchFlightsParams) {
	writeJSON(w, 404, msg("not a Service Provider"))
}

// GetFlightDetails is the SP's.
func (s dssServer) GetFlightDetails(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, 404, msg("not a Service Provider"))
}

// PostIdentificationServiceArea is a Display Provider's.
func (s dssServer) PostIdentificationServiceArea(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, 404, msg("not a Display Provider"))
}

func (d *DSS) getAvailability(w http.ResponseWriter, r *http.Request) {
	uss := r.PathValue("uss_id")
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.availability[uss]
	if !ok {
		a = f3548.UssAvailabilityStatusResponse{Status: f3548.UssAvailabilityStatus{Uss: uss, Availability: f3548.Unknown}, Version: ""}
	}
	writeJSON(w, 200, a)
}

func (d *DSS) putAvailability(w http.ResponseWriter, r *http.Request) {
	uss := r.PathValue("uss_id")
	var body f3548.SetUssAvailabilityStatusParameters
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !body.Availability.Valid() {
		writeJSON(w, 400, map[string]string{"message": "body"})
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if cur := d.availability[uss]; cur.Version != body.OldVersion {
		writeJSON(w, 409, map[string]string{"message": "old_version"})
		return
	}
	a := f3548.UssAvailabilityStatusResponse{Status: f3548.UssAvailabilityStatus{Uss: uss, Availability: body.Availability},
		Version: strconv.FormatInt(time.Now().UnixNano(), 10)}
	d.availability[uss] = a
	writeJSON(w, 200, a)
}

// ---- Service Provider ------------------------------------------------

// SetFlights sets the flights served and their details.
func (s *SP) SetFlights(flights []f3411.RIDFlight, details map[string]f3411.RIDFlightDetails) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flights = flights
	if details != nil {
		s.details = details
	}
}

// SetDown makes every call fail with 503.
func (s *SP) SetDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

// SetStatus makes /uss/flights answer status (413) instead; 0 serves.
func (s *SP) SetStatus(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

// SetDelay delays every answer.
func (s *SP) SetDelay(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

// Counts are the polls and details requests served.
func (s *SP) Counts() (polls, details int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.polls, s.detailsN
}

// Claims are the claims of every call so far.
func (s *SP) Claims() []Claims {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Claims(nil), s.claims...)
}

// Views are the views polled so far.
func (s *SP) Views() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.views...)
}

type spServer struct{ s *SP }

func (x spServer) wait(r *http.Request) (bool, int) {
	x.s.mu.Lock()
	x.s.claims = append(x.s.claims, readClaims(r))
	down, status, delay := x.s.down, x.s.status, x.s.delay
	x.s.mu.Unlock()
	if delay > 0 {
		select {
		case <-r.Context().Done():
			return false, 0
		case <-time.After(delay):
		}
	}
	return down, status
}

// SearchFlights implements ridapi.ServerInterface.
func (x spServer) SearchFlights(w http.ResponseWriter, r *http.Request, p f3411.SearchFlightsParams) {
	down, status := x.wait(r)
	x.s.mu.Lock()
	x.s.polls++
	x.s.views = append(x.s.views, p.View)
	flights := append([]f3411.RIDFlight(nil), x.s.flights...)
	ts := x.s.respTS()
	x.s.mu.Unlock()
	switch {
	case down:
		writeJSON(w, 503, msg("down"))
		return
	case status != 0:
		writeJSON(w, status, msg(http.StatusText(status)))
		return
	}
	box, err := dp.ParseView(p.View, "view")
	if err != nil {
		writeJSON(w, 400, msg(err.Error()))
		return
	}
	in := []f3411.RIDFlight{}
	for _, f := range flights {
		if f.CurrentState != nil && dp.Contains(box, f.CurrentState.Position.LatLon()) {
			in = append(in, f)
		}
	}
	writeJSON(w, 200, f3411.GetFlightsResponse{Flights: &in, Timestamp: f3411.Time{Format: f3411.RFC3339, Value: ts.UTC()}})
}

// GetFlightDetails implements ridapi.ServerInterface.
func (x spServer) GetFlightDetails(w http.ResponseWriter, r *http.Request, id string) {
	down, _ := x.wait(r)
	x.s.mu.Lock()
	x.s.detailsN++
	d, ok := x.s.details[id]
	x.s.mu.Unlock()
	if down {
		writeJSON(w, 503, msg("down"))
		return
	}
	if !ok {
		writeJSON(w, 404, msg("no such flight"))
		return
	}
	writeJSON(w, 200, f3411.GetFlightDetailsResponse{Details: d})
}

// SearchIdentificationServiceAreas is the DSS's.
func (x spServer) SearchIdentificationServiceAreas(w http.ResponseWriter, _ *http.Request, _ f3411.SearchIdentificationServiceAreasParams) {
	writeJSON(w, 404, msg("not a DSS"))
}

// CreateSubscription is the DSS's.
func (x spServer) CreateSubscription(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, 404, msg("not a DSS"))
}

// UpdateSubscription is the DSS's.
func (x spServer) UpdateSubscription(w http.ResponseWriter, _ *http.Request, _, _ string) {
	writeJSON(w, 404, msg("not a DSS"))
}

// DeleteSubscription is the DSS's.
func (x spServer) DeleteSubscription(w http.ResponseWriter, _ *http.Request, _, _ string) {
	writeJSON(w, 404, msg("not a DSS"))
}

// PostIdentificationServiceArea is a Display Provider's.
func (x spServer) PostIdentificationServiceArea(w http.ResponseWriter, _ *http.Request, _ string) {
	writeJSON(w, 404, msg("not a Display Provider"))
}

// Notify posts an ISA change to every subscriber, as F3411 has the
// ISA's owner do: area nil is a deletion. token gives the bearer for a
// subscriber's base URL. It returns each subscriber's status.
func Notify(ctx context.Context, subscribers []f3411.SubscriberToNotify, id string, area *f3411.IdentificationServiceArea,
	extents *f3411.Volume4D, token func(base string) string) (map[string]int, error) {
	out := map[string]int{}
	for _, s := range subscribers {
		body, err := json.Marshal(f3411.PutIdentificationServiceAreaNotificationParameters{
			ServiceArea: area, Extents: extents, Subscriptions: s.Subscriptions})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.Url, "/")+"/uss/identification_service_areas/"+id, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token(s.Url))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		_ = resp.Body.Close()
		out[s.Url] = resp.StatusCode
	}
	return out, nil
}
