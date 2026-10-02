package cisp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/cisp/cispclient"
)

// Defaults of ClientConfig.
const (
	// DefaultTimeout bounds one call to the CISP.
	DefaultTimeout = 10 * time.Second
	// MaxErrorBodyBytes is how much of an error answer is read.
	MaxErrorBodyBytes = 8 << 10
	// MaxBodyBytes bounds a dataset answer: what ed318.Parse reads at
	// most by default, so nothing larger could be accepted (E-10).
	MaxBodyBytes = 4 << 20
)

// Headers of the CISP's answers (the pinned api/clients/cisp.yaml).
const (
	HeaderJWSSignature       = "X-JWS-Signature"
	HeaderCISVersion         = "X-CIS-Version"
	HeaderPublisherSignature = "X-Publisher-Signature"
	HeaderPublisherKID       = "X-Publisher-Kid"
)

// TokenSource hands out an ecosystem token for the host of baseURL
// (M18) with the scopes; tokens.Client implements it.
type TokenSource interface {
	Token(ctx context.Context, baseURL string, scopes ...string) (string, error)
}

// ErrNoTokenSource is returned by every call of a client built without
// a token source: the CISP authenticates every call.
var ErrNoTokenSource = errors.New("no token client for the CISP (CISP_CLIENT_SECRET_FILE)")

// ClientConfig configures a Client.
type ClientConfig struct {
	// BaseURL is CISP_BASE_URL: https, or http only to a loopback host.
	BaseURL string
	Tokens  TokenSource
	// HTTPClient is used for every call; nil is a client that never
	// follows a redirect (a 3xx is an answer, never a new target).
	HTTPClient *http.Client
	Timeout    time.Duration
}

// Client calls the CISP through the generated client of the pinned
// api/clients/cisp.yaml.
type Client struct {
	cfg  ClientConfig
	base *url.URL
	gen  *cispclient.Client
}

// NewClient builds a Client. A base URL that is not https (or http to a
// loopback host, for tests) is refused naming CISP_BASE_URL: pulls go
// only over https to the configured CISP.
func NewClient(cfg ClientConfig) (*Client, error) {
	u, err := CheckBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	c := &Client{cfg: cfg, base: u}
	c.gen, err = cispclient.NewClient(strings.TrimRight(cfg.BaseURL, "/"), cispclient.WithHTTPClient(cfg.HTTPClient))
	if err != nil {
		return nil, fmt.Errorf("CISP client: %w", err)
	}
	return c, nil
}

// CheckBaseURL parses CISP_BASE_URL: an absolute https URL without user
// information, query or fragment, or http to a loopback address.
func CheckBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Host == "":
		return nil, core.Fieldf("CISP_BASE_URL", "not an absolute URL")
	case u.User != nil || u.RawQuery != "" || u.Fragment != "":
		return nil, core.Fieldf("CISP_BASE_URL", "must carry no user information, query or fragment")
	case u.Scheme == "https":
		return u, nil
	case u.Scheme == "http" && loopback(u.Hostname()):
		return u, nil
	}
	return nil, core.Fieldf("CISP_BASE_URL", "must be https (http only to a loopback host)")
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// BaseURL is the configured base URL.
func (c *Client) BaseURL() string { return c.cfg.BaseURL }

// Host is the configured CISP's host (without its port).
func (c *Client) Host() string { return c.base.Hostname() }

// auth adds a bearer for the scope to one request.
func (c *Client) auth(scope string) cispclient.RequestEditorFn {
	return func(ctx context.Context, req *http.Request) error {
		if c.cfg.Tokens == nil {
			return ErrNoTokenSource
		}
		tok, err := c.cfg.Tokens.Token(ctx, c.cfg.BaseURL, scope)
		if err != nil {
			return fmt.Errorf("token for the CISP: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		return nil
	}
}

// StatusError is an answer of the CISP other than the ones a call
// expects: its status and the problem's slug and detail, when it sent
// one.
type StatusError struct {
	Status int
	Slug   string
	Detail string
	Fields []string
}

func (e *StatusError) Error() string {
	s := "CISP answered " + strconv.Itoa(e.Status)
	if e.Slug != "" {
		s += " " + e.Slug
	}
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if len(e.Fields) > 0 {
		s += " (" + strings.Join(e.Fields, "; ") + ")"
	}
	return s
}

func statusError(resp *http.Response) *StatusError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes))
	e := &StatusError{Status: resp.StatusCode}
	var p cispclient.Problem
	if json.Unmarshal(body, &p) == nil {
		if i := strings.LastIndex(p.Type, "/"); i >= 0 {
			e.Slug = short(p.Type[i+1:])
		}
		if p.Detail != nil {
			e.Detail = short(*p.Detail)
		}
		if p.Errors != nil {
			for i, fe := range *p.Errors {
				if i == 5 {
					e.Fields = append(e.Fields, "...")
					break
				}
				e.Fields = append(e.Fields, short(fe.Field+": "+fe.Reason))
			}
		}
	}
	return e
}

// short bounds a text taken from an answer for a log line or a status.
func short(s string) string {
	r := []rune(s)
	if len(r) > 200 {
		return string(r[:199]) + "…"
	}
	return s
}

// PublishAnswer is the CISP's answer to a PUT of a publication.
type PublishAnswer struct {
	Status int
	// ETag is the answer's ETag: the new or current version's (2xx), or
	// the current one (412).
	ETag string
	// Version is the version the CISP holds after a 2xx.
	Version   int64
	Unchanged bool
	// Problem is the CISP's refusal (any status but 2xx).
	Problem *StatusError
}

// Publish is PUT /v1/publications/{dataset} with the payload, its
// detached JWS and If-Match ifMatch, under a token with the dataset's
// publish scope. Any answer is returned; only a failure to get one is an
// error.
func (c *Client) Publish(ctx context.Context, ds Dataset, payload []byte, contentType, ifMatch, signature string) (PublishAnswer, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	params := &cispclient.PutPublicationParams{IfMatch: &ifMatch, XJWSSignature: &signature}
	resp, err := c.gen.PutPublicationWithBody(ctx, cispclient.PutPublicationParamsDataset(ds), params, contentType,
		bytes.NewReader(payload), c.auth(ds.PublishScope()))
	if err != nil {
		return PublishAnswer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	a := PublishAnswer{Status: resp.StatusCode, ETag: resp.Header.Get("ETag")}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		a.Problem = statusError(resp)
		return a, nil
	}
	var res cispclient.PublicationResult
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBodyBytes*8))
	if err != nil {
		return PublishAnswer{}, fmt.Errorf("reading the answer: %w", err)
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return PublishAnswer{}, fmt.Errorf("the CISP's %d answer does not decode: %s", resp.StatusCode, short(err.Error()))
	}
	a.Version = res.Version
	a.Unchanged = res.Unchanged != nil && *res.Unchanged
	if a.ETag == "" {
		a.ETag = res.Etag
	}
	return a, nil
}

// ParseETag reads the version of a CISP ETag ("zones:12", quotes
// included, for ds).
func ParseETag(ds Dataset, etag string) (int64, bool) {
	s := strings.TrimSpace(strings.TrimPrefix(etag, "W/"))
	s = strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`)
	prefix := string(ds) + ":"
	if !strings.HasPrefix(s, prefix) {
		return 0, false
	}
	v, err := strconv.ParseInt(s[len(prefix):], 10, 64)
	return v, err == nil && v >= 0
}

// ETagOf is the CISP's ETag of version v of ds, quotes included.
func ETagOf(ds Dataset, v int64) string {
	return `"` + string(ds) + ":" + strconv.FormatInt(v, 10) + `"`
}

// LatestVersion is the CISP's newest version of ds with the SHA-256 of
// its bytes (GET /v1/publications/{dataset}?limit=1, as its publisher);
// ok is false before the first version.
func (c *Client) LatestVersion(ctx context.Context, ds Dataset) (version int64, bodySHA256 string, ok bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	limit := 1
	resp, err := c.gen.ListPublications(ctx, cispclient.ListPublicationsParamsDataset(ds),
		&cispclient.ListPublicationsParams{Limit: &limit}, c.auth(ds.PublishScope()))
	if err != nil {
		return 0, "", false, err
	}
	var list cispclient.PublicationVersionList
	if err := decode(resp, http.StatusOK, &list); err != nil {
		return 0, "", false, err
	}
	if len(list.Versions) == 0 {
		return 0, "", false, nil
	}
	return list.Versions[0].Version, list.Versions[0].BodySha256, true, nil
}

// Heartbeat is POST /v1/publishers/heartbeat {sent_at} under a
// cis.publish:* token (the authority's zones scope; active_refs is
// omitted: the authority publishes no restrictions). It returns the
// CISP's status, or an error when there was no answer.
func (c *Client) Heartbeat(ctx context.Context, sentAt time.Time) (int, *StatusError, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.gen.PostPublisherHeartbeat(ctx, cispclient.PostPublisherHeartbeatJSONRequestBody{SentAt: sentAt.UTC()},
		c.auth(DatasetZones.PublishScope()))
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil, nil
	}
	return resp.StatusCode, statusError(resp), nil
}

// Fetched is one answer to a dataset read.
type Fetched struct {
	// Status is 200, 304 (If-None-Match named the current version) or
	// 404 with the problem no_version (the dataset has none yet).
	Status int
	ETag   string
	// Version is X-CIS-Version (0 when absent).
	Version int64
	Body    []byte
	// PublisherSignature and PublisherKID are X-Publisher-Signature and
	// X-Publisher-Kid ("" when absent; only a version read sends them).
	PublisherSignature string
	PublisherKID       string
}

// Head is HEAD /v1/{dataset} with If-None-Match etag (the 60 s
// reconciliation).
func (c *Client) Head(ctx context.Context, ds Dataset, etag string) (Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	p := &cispclient.HeadDatasetParams{}
	if etag != "" {
		p.IfNoneMatch = &etag
	}
	resp, err := c.gen.HeadDataset(ctx, cispclient.HeadDatasetParamsDataset(ds), p, c.auth(ScopeRead))
	if err != nil {
		return Fetched{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	f, err := fetchedHeaders(resp)
	if err != nil {
		return Fetched{}, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNotModified:
		return f, nil
	case http.StatusNotFound:
		// A HEAD answer has no body to name no_version: the GET says.
		return f, nil
	}
	return Fetched{}, &StatusError{Status: resp.StatusCode}
}

// GetDataset is GET /v1/{dataset}, unfiltered, or the delta from
// sinceVersion when it is not nil, with If-None-Match etag when not
// empty.
func (c *Client) GetDataset(ctx context.Context, ds Dataset, sinceVersion *int64, etag string) (Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	p := &cispclient.GetDatasetParams{SinceVersion: sinceVersion}
	if etag != "" {
		p.IfNoneMatch = &etag
	}
	resp, err := c.gen.GetDataset(ctx, cispclient.GetDatasetParamsDataset(ds), p, c.auth(ScopeRead))
	if err != nil {
		return Fetched{}, err
	}
	return read(resp)
}

// GetVersion is GET /v1/{dataset}/versions/{v}: the version's bytes as
// published, with the publisher's detached JWS.
func (c *Client) GetVersion(ctx context.Context, ds Dataset, v int64) (Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.gen.GetDatasetVersion(ctx, cispclient.GetDatasetVersionParamsDataset(ds), v,
		&cispclient.GetDatasetVersionParams{}, c.auth(ScopeRead))
	if err != nil {
		return Fetched{}, err
	}
	return read(resp)
}

// ErrPullURLRefused is returned by CheckPullURL for a pull_url that is
// not https on the configured CISP's host and port.
var ErrPullURLRefused = errors.New("pull_url refused")

// CheckPullURL says whether raw may be followed: an absolute https URL
// with the host and port of CISP_BASE_URL (a missing port is the
// scheme's default) and no user information. Plain http is never
// followed, even to a loopback CISP: the dataset is then read from the
// base URL.
func (c *Client) CheckPullURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil || !u.IsAbs() || u.Host == "":
		return nil, fmt.Errorf("%w: not an absolute URL", ErrPullURLRefused)
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: scheme %q, only https is followed", ErrPullURLRefused, short(u.Scheme))
	case u.Scheme != c.base.Scheme:
		return nil, fmt.Errorf("%w: the CISP's base URL is %s", ErrPullURLRefused, c.base.Scheme)
	case u.User != nil:
		return nil, fmt.Errorf("%w: it carries user information", ErrPullURLRefused)
	case !strings.EqualFold(u.Hostname(), c.base.Hostname()):
		return nil, fmt.Errorf("%w: not on the CISP's host", ErrPullURLRefused)
	case effectivePort(u) != effectivePort(c.base):
		return nil, fmt.Errorf("%w: port %s, the CISP's is %s", ErrPullURLRefused, short(effectivePort(u)), effectivePort(c.base))
	}
	return u, nil
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// GetURL reads a pull_url CheckPullURL accepts; any other is never
// requested.
func (c *Client) GetURL(ctx context.Context, raw string) (Fetched, error) {
	u, err := c.CheckPullURL(raw)
	if err != nil {
		return Fetched{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return Fetched{}, err
	}
	if err := c.auth(ScopeRead)(ctx, req); err != nil {
		return Fetched{}, err
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return Fetched{}, err
	}
	return read(resp)
}

func fetchedHeaders(resp *http.Response) (Fetched, error) {
	f := Fetched{Status: resp.StatusCode, ETag: resp.Header.Get("ETag"),
		PublisherSignature: resp.Header.Get(HeaderPublisherSignature), PublisherKID: resp.Header.Get(HeaderPublisherKID)}
	if v := resp.Header.Get(HeaderCISVersion); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return Fetched{}, errors.New(HeaderCISVersion + " is not a version")
		}
		f.Version = n
	}
	return f, nil
}

func read(resp *http.Response) (Fetched, error) {
	defer func() { _ = resp.Body.Close() }()
	f, err := fetchedHeaders(resp)
	if err != nil {
		return Fetched{}, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return f, nil
	case http.StatusNotFound:
		se := statusError(resp)
		if se.Slug == "no_version" {
			return f, nil
		}
		return Fetched{}, se
	default:
		return Fetched{}, statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return Fetched{}, fmt.Errorf("reading the answer: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return Fetched{}, fmt.Errorf("the answer is longer than %d bytes", MaxBodyBytes)
	}
	f.Body = body
	return f, nil
}

func decode(resp *http.Response, want int, v any) error {
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != want {
		return statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("reading the answer: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return fmt.Errorf("the answer is longer than %d bytes", MaxBodyBytes)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("the answer does not decode: %s", short(err.Error()))
	}
	return nil
}

// Subscribe makes sure this system has one subscription with callback
// for datasets within bbox (nil: everywhere), and returns it. It is
// idempotent: it lists the caller's subscriptions and reuses the one
// with the same callback, patching it when its datasets or box differ or
// it is suspended (a PATCH re-activates it); only when there is none
// does it create one.
func (c *Client) Subscribe(ctx context.Context, callback string, datasets []Dataset, bbox []float64) (cispclient.Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	resp, err := c.gen.ListSubscriptions(ctx, c.auth(ScopeRead))
	if err != nil {
		return cispclient.Subscription{}, err
	}
	var list cispclient.SubscriptionList
	if err := decode(resp, http.StatusOK, &list); err != nil {
		return cispclient.Subscription{}, err
	}
	want := make([]string, len(datasets))
	for i, d := range datasets {
		want[i] = string(d)
	}
	slices.Sort(want)
	for i := range list.Subscriptions {
		s := &list.Subscriptions[i]
		if s.CallbackUrl != callback || s.Status == cispclient.SubscriptionStatusDeleted {
			continue
		}
		have := make([]string, len(s.Datasets))
		for j, d := range s.Datasets {
			have[j] = string(d)
		}
		slices.Sort(have)
		var hb []float64
		if s.Bbox != nil {
			hb = *s.Bbox
		}
		if slices.Equal(have, want) && slices.Equal(hb, bbox) && s.Status != cispclient.SubscriptionStatusSuspended {
			return *s, nil
		}
		ds := make([]cispclient.SubscriptionPatchDatasets, len(datasets))
		for j, d := range datasets {
			ds[j] = cispclient.SubscriptionPatchDatasets(d)
		}
		b := bbox
		if b == nil {
			b = []float64{}
		}
		resp, err := c.gen.PatchSubscription(ctx, s.Id, cispclient.SubscriptionPatch{Datasets: &ds, Bbox: &b}, c.auth(ScopeRead))
		if err != nil {
			return cispclient.Subscription{}, err
		}
		var out cispclient.Subscription
		err = decode(resp, http.StatusOK, &out)
		return out, err
	}
	ds := make([]cispclient.SubscriptionCreateDatasets, len(datasets))
	for i, d := range datasets {
		ds[i] = cispclient.SubscriptionCreateDatasets(d)
	}
	body := cispclient.SubscriptionCreate{CallbackUrl: callback, Datasets: ds}
	if bbox != nil {
		b := slices.Clone(bbox)
		body.Bbox = &b
	}
	resp, err = c.gen.CreateSubscription(ctx, body, c.auth(ScopeRead))
	if err != nil {
		return cispclient.Subscription{}, err
	}
	var out cispclient.Subscription
	err = decode(resp, http.StatusCreated, &out)
	return out, err
}
