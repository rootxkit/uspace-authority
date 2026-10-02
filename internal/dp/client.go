package dp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/dp/ridapi"
)

// Tokens gives the bearer token for a call to the system published at
// baseURL (tokens.Client: aud is that URL's host, M18).
type Tokens interface {
	Token(ctx context.Context, baseURL string, scopes ...string) (string, error)
}

// ErrNoTokens is every outbound call of a Display Provider without a
// client secret: refused locally and counted.
var ErrNoTokens = errors.New("no client secret for the Display Provider's tokens (DP_CLIENT_SECRET_FILE)")

// ErrPlainHTTP refuses a base URL that is plain HTTP to a host other
// than a loopback one (R-14: plain HTTP refused except to localhost).
var ErrPlainHTTP = errors.New("plain http refused except to a loopback host")

// HTTPError is an answer other than the one expected.
type HTTPError struct {
	Op     string
	Status int
}

func (e *HTTPError) Error() string { return fmt.Sprintf("%s: HTTP %d", e.Op, e.Status) }

// StatusOf is the HTTP status of err, 0 when it is not an HTTPError.
func StatusOf(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// ErrTooLarge is a body over the bound.
var ErrTooLarge = errors.New("response larger than the bound")

// CheckBaseURL refuses a base URL that is not absolute http(s), or is
// plain http to a host other than a loopback one.
func CheckBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
		return nil, core.Fieldf("uss_base_url", "not an absolute http(s) URL")
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return nil, ErrPlainHTTP
	}
	return u, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Client makes the Display Provider's F3411 calls through the client
// generated from the pinned contract (internal/dp/ridapi), with a bearer
// token per target (rid.display_provider, aud the target's host), a
// bounded body and core's validating readers.
type Client struct {
	HTTP    *http.Client
	Tokens  Tokens
	MaxBody int64
	// DSS is the DSS base URL (F3411 is under /rid/v2).
	DSS string
}

func (c *Client) std(base string) (*ridapi.StdClient, error) {
	if _, err := CheckBaseURL(base); err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	return ridapi.NewClient(base, ridapi.WithHTTPClient(hc))
}

// auth adds the bearer token for target.
func (c *Client) auth(target string) ridapi.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		if c.Tokens == nil {
			return ErrNoTokens
		}
		tok, err := c.Tokens.Token(ctx, target, string(f3411.ScopeDisplayProvider))
		if err != nil {
			return fmt.Errorf("token for %s: %w", hostOf(target), err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		return nil
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	return u.Host
}

// read takes the body of resp, at most MaxBody bytes, and refuses any
// status but 200.
func (c *Client) read(op string, resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	limit := c.MaxBody
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read: %w", op, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: %w (%d bytes)", op, ErrTooLarge, limit)
	}
	if resp.StatusCode != http.StatusOK {
		return body, &HTTPError{Op: op, Status: resp.StatusCode}
	}
	return body, nil
}

func (c *Client) dssBase() string { return strings.TrimSuffix(c.DSS, "/") + "/rid/v2" }

// SearchISAs is GET /dss/identification_service_areas?area= for b
// between now and until.
func (c *Client) SearchISAs(ctx context.Context, b Box, now, until time.Time) ([]f3411.IdentificationServiceArea, error) {
	sc, err := c.std(c.dssBase())
	if err != nil {
		return nil, err
	}
	resp, err := sc.SearchIdentificationServiceAreas(ctx, &f3411.SearchIdentificationServiceAreasParams{
		Area: AreaParam(b), EarliestTime: now.UTC(), LatestTime: until.UTC(),
	}, c.auth(c.DSS))
	if err != nil {
		return nil, err
	}
	body, err := c.read("search ISAs", resp)
	if err != nil {
		return nil, err
	}
	var r f3411.SearchIdentificationServiceAreasResponse
	if err := decodeBounded(body, &r); err != nil {
		return nil, err
	}
	if r.ServiceAreas == nil {
		return nil, nil
	}
	return *r.ServiceAreas, nil
}

// PutSubscription creates (version empty) or renews the subscription id
// over b from start to end, notifications to ussBaseURL.
func (c *Client) PutSubscription(ctx context.Context, id, version string, b Box, start, end time.Time, ussBaseURL string) (*f3411.PutSubscriptionResponse, error) {
	sc, err := c.std(c.dssBase())
	if err != nil {
		return nil, err
	}
	ext := Volume(b, start, end)
	var resp *http.Response
	if version == "" {
		resp, err = sc.CreateSubscription(ctx, id, f3411.CreateSubscriptionParameters{Extents: ext, UssBaseUrl: ussBaseURL}, c.auth(c.DSS))
	} else {
		resp, err = sc.UpdateSubscription(ctx, id, version, f3411.UpdateSubscriptionParameters{Extents: ext, UssBaseUrl: ussBaseURL}, c.auth(c.DSS))
	}
	if err != nil {
		return nil, err
	}
	body, err := c.read("put subscription", resp)
	if err != nil {
		return nil, err
	}
	var r f3411.PutSubscriptionResponse
	if err := decodeBounded(body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// DeleteSubscription removes the subscription id at version.
func (c *Client) DeleteSubscription(ctx context.Context, id, version string) error {
	sc, err := c.std(c.dssBase())
	if err != nil {
		return err
	}
	resp, err := sc.DeleteSubscription(ctx, id, version, c.auth(c.DSS))
	if err != nil {
		return err
	}
	_, err = c.read("delete subscription", resp)
	return err
}

// Flights is GET {sp}/uss/flights?view= for b, read through core's
// validating reader (f3411.UnmarshalGetFlightsResponse), with each
// flight's bytes as received (for ussp_flights).
func (c *Client) Flights(ctx context.Context, sp string, b Box) (*f3411.GetFlightsResponse, []json.RawMessage, error) {
	sc, err := c.std(sp)
	if err != nil {
		return nil, nil, err
	}
	resp, err := sc.SearchFlights(ctx, &f3411.SearchFlightsParams{View: ViewParam(b)}, c.auth(sp))
	if err != nil {
		return nil, nil, err
	}
	body, err := c.read("flights", resp)
	if err != nil {
		return nil, nil, err
	}
	return ParseFlights(body)
}

// ParseFlights reads a GetFlightsResponse through core's validating
// reader and keeps every flight's bytes as received, in order.
func ParseFlights(body []byte) (*f3411.GetFlightsResponse, []json.RawMessage, error) {
	r, err := f3411.UnmarshalGetFlightsResponse(body)
	if err != nil {
		return nil, nil, err
	}
	var raw struct {
		Flights []json.RawMessage `json:"flights"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, core.Fieldf("response", "not a GetFlightsResponse")
	}
	n := 0
	if r.Flights != nil {
		n = len(*r.Flights)
	}
	if len(raw.Flights) != n {
		return nil, nil, core.Fieldf("response.flights", "read %d flights, %d raw", n, len(raw.Flights))
	}
	return r, raw.Flights, nil
}

// Details is GET {sp}/uss/flights/{id}/details, with the details' bytes
// as received.
func (c *Client) Details(ctx context.Context, sp, id string) (*f3411.RIDFlightDetails, json.RawMessage, error) {
	sc, err := c.std(sp)
	if err != nil {
		return nil, nil, err
	}
	resp, err := sc.GetFlightDetails(ctx, id, c.auth(sp))
	if err != nil {
		return nil, nil, err
	}
	body, err := c.read("details", resp)
	if err != nil {
		return nil, nil, err
	}
	d, err := ParseDetails(body)
	if err != nil {
		return nil, nil, err
	}
	var raw struct {
		Details json.RawMessage `json:"details"`
	}
	_ = json.Unmarshal(body, &raw) // ParseDetails read the same bytes
	return d, raw.Details, nil
}

// maxDetailsBytes bounds one details body; F3411 details are a few
// hundred bytes.
const maxDetailsBytes = 64 << 10

// maxIDBytes bounds every identifier taken from a details body.
const maxIDBytes = 256

// ParseDetails reads a GetFlightDetailsResponse from untrusted bytes.
// core has no validating reader for details (spec gap, WP-14 PR): this
// one bounds the body and every identifier the Display Provider uses
// (the serial, the registration, the operator id), refuses an operator
// location outside WGS84, and never panics (FuzzParseDetails).
func ParseDetails(raw []byte) (*f3411.RIDFlightDetails, error) {
	if len(raw) > maxDetailsBytes {
		return nil, core.Fieldf("details", "is %d bytes; at most %d", len(raw), maxDetailsBytes)
	}
	var r f3411.GetFlightDetailsResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, core.Fieldf("details", "not a GetFlightDetailsResponse")
	}
	d := &r.Details
	if d.Id == "" || len(d.Id) > maxIDBytes {
		return nil, core.Fieldf("details.id", "required, at most %d bytes", maxIDBytes)
	}
	for name, v := range map[string]*string{"details.operator_id": d.OperatorId} {
		if v != nil && len(*v) > maxIDBytes {
			return nil, core.Fieldf(name, "longer than %d bytes", maxIDBytes)
		}
	}
	if u := d.UasId; u != nil {
		for name, v := range map[string]*string{
			"details.uas_id.serial_number": u.SerialNumber, "details.uas_id.registration_id": u.RegistrationId,
			"details.uas_id.utm_id": u.UtmId, "details.uas_id.specific_session_id": u.SpecificSessionId,
		} {
			if v != nil && len(*v) > maxIDBytes {
				return nil, core.Fieldf(name, "longer than %d bytes", maxIDBytes)
			}
		}
	}
	if ol := d.OperatorLocation; ol != nil && !ol.Position.LatLon().Valid() {
		return nil, core.Fieldf("details.operator_location.position", "is not a valid WGS84 position")
	}
	return d, nil
}

// decodeBounded decodes a DSS answer already bounded by read.
func decodeBounded(body []byte, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return core.Fieldf("response", "not the expected F3411 shape")
	}
	return nil
}

// NoRedirectClient is the outbound HTTP client: a redirect is never
// followed (a Service Provider cannot send the token elsewhere).
func NoRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
