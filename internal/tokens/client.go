package tokens

import (
	"container/list"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
)

// Defaults of ClientConfig.
const (
	DefaultClientMaxEntries    = 64
	DefaultClientFetchTimeout  = 10 * time.Second
	DefaultClientMaxBodyBytes  = 64 << 10
	DefaultClientRetryInterval = 5 * time.Second
	// assertionTTL is the lifetime of a private_key_jwt assertion this
	// client signs (one request).
	assertionTTL = time.Minute
)

// Counters of the outbound client.
const (
	CounterClientFetched     = "token_client_fetched"      // a token obtained
	CounterClientFetchFailed = "token_client_fetch_failed" // a token request failed
	CounterClientPrefetched  = "token_client_prefetched"   // a refresh started at half the lifetime
	CounterClientEvicted     = "token_client_evicted"      // a cached token dropped for the bound
)

// ClientConfig configures a Client. Exactly one of ClientSecret and
// AssertionKey is set.
type ClientConfig struct {
	// TokenURL is the issuer's /oauth/token.
	TokenURL string
	ClientID string
	// ClientSecret authenticates with client_secret_post.
	ClientSecret string
	// AssertionKey authenticates with private_key_jwt: each request
	// carries an assertion signed by core's Issuer (iss = sub = ClientID,
	// aud = TokenURL, one minute, a fresh jti).
	AssertionKey *auth.SigningKey
	HTTPClient   *http.Client
	Now          func() time.Time
	// MaxEntries bounds the cached tokens (one per audience and scope
	// set; E-10).
	MaxEntries int
	// FetchTimeout bounds one token request.
	FetchTimeout time.Duration
	// MaxBodyBytes bounds a token response.
	MaxBodyBytes int64
	// RetryInterval is the least time between two failed background
	// refreshes of one entry.
	RetryInterval time.Duration
}

// Client is the outbound client-credentials helper every work package
// uses to call another system (the CISP, a USSP, the DSS, the ANSP): it
// asks this ecosystem's issuer for a token whose aud is the host of the
// target's base URL (M18), one token per audience and scope set, kept
// until it expires. From half its lifetime on, a call is served the
// cached token and starts one refresh in the background on a context of
// its own (E-14, T5: an issuer outage is felt only when a token
// actually runs out). A call without a usable token joins the one
// request in flight for its key and waits for it or for its own
// context; cancelling never fails the request for the others. Safe for
// concurrent use.
type Client struct {
	cfg      ClientConfig
	counters core.Counters
	issuer   *auth.Issuer // assertion signer

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = most recently used
}

type entry struct {
	key       string
	audience  string
	scopes    []string
	token     string
	issued    time.Time
	expires   time.Time
	inflight  chan struct{}
	err       error
	lastError time.Time
}

// NewClient validates c.
func NewClient(c ClientConfig) (*Client, error) {
	u, err := url.Parse(c.TokenURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, core.Fieldf("token_url", "not an absolute http(s) URL")
	}
	if _, err := SystemOf(c.ClientID); err != nil {
		return nil, err
	}
	if (c.ClientSecret == "") == (c.AssertionKey == nil) {
		return nil, core.Fieldf("client_secret", "set exactly one of a client secret and an assertion key")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: DefaultClientFetchTimeout}
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.MaxEntries <= 0 {
		c.MaxEntries = DefaultClientMaxEntries
	}
	if c.FetchTimeout <= 0 {
		c.FetchTimeout = DefaultClientFetchTimeout
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = DefaultClientMaxBodyBytes
	}
	if c.RetryInterval <= 0 {
		c.RetryInterval = DefaultClientRetryInterval
	}
	cl := &Client{cfg: c, entries: map[string]*list.Element{}, order: list.New()}
	if c.AssertionKey != nil {
		if cl.issuer, err = auth.NewIssuer(c.ClientID, c.AssertionKey.Key, c.AssertionKey.KID); err != nil {
			return nil, err
		}
	}
	return cl, nil
}

// Counters returns the client's counters.
func (c *Client) Counters() *core.Counters { return &c.counters }

// Len is the number of cached tokens.
func (c *Client) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// Token returns a token for calling the system published at baseURL
// with scopes: aud is that URL's host.
func (c *Client) Token(ctx context.Context, baseURL string, scopes ...string) (string, error) {
	aud, err := AudienceOf(baseURL)
	if err != nil {
		return "", err
	}
	return c.TokenFor(ctx, aud, scopes)
}

// TokenFor returns a token for audience (a host) and scopes.
func (c *Client) TokenFor(ctx context.Context, audience string, scopes []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	sorted := slices.Clone(scopes)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	if len(sorted) == 0 {
		return "", core.Fieldf("scope", "at least one scope")
	}
	key := audience + " " + strings.Join(sorted, " ")
	now := c.cfg.Now()

	c.mu.Lock()
	e := c.lookup(key, audience, sorted)
	if e.token != "" && now.Before(e.expires) {
		tok := e.token
		half := e.issued.Add(e.expires.Sub(e.issued) / 2)
		if !now.Before(half) && e.inflight == nil && now.Sub(e.lastError) >= c.cfg.RetryInterval {
			c.counters.Inc(CounterClientPrefetched)
			c.start(e)
		}
		c.mu.Unlock()
		return tok, nil
	}
	done := e.inflight
	if done == nil {
		done = c.start(e)
	}
	c.mu.Unlock()

	select {
	case <-done:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.token != "" && c.cfg.Now().Before(e.expires) {
		return e.token, nil
	}
	if e.err != nil {
		return "", e.err
	}
	return "", errors.New("token request failed")
}

// lookup returns the entry of key, creating it and evicting the least
// recently used entry with no request in flight beyond the bound. The
// caller holds mu.
func (c *Client) lookup(key, audience string, scopes []string) *entry {
	if el, ok := c.entries[key]; ok {
		c.order.MoveToFront(el)
		return el.Value.(*entry)
	}
	for c.order.Len() >= c.cfg.MaxEntries {
		victim := c.order.Back()
		for victim != nil && victim.Value.(*entry).inflight != nil {
			victim = victim.Prev()
		}
		if victim == nil {
			break
		}
		c.order.Remove(victim)
		delete(c.entries, victim.Value.(*entry).key)
		c.counters.Inc(CounterClientEvicted)
	}
	e := &entry{key: key, audience: audience, scopes: scopes}
	c.entries[key] = c.order.PushFront(e)
	return e
}

// start launches the request for e on a context of its own; the caller
// holds mu.
func (c *Client) start(e *entry) chan struct{} {
	done := make(chan struct{})
	e.inflight = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), c.cfg.FetchTimeout)
		defer cancel()
		tok, ttl, err := c.fetch(ctx, e.audience, e.scopes)
		now := c.cfg.Now()
		c.mu.Lock()
		if err != nil {
			c.counters.Inc(CounterClientFetchFailed)
			e.err, e.lastError = err, now
		} else {
			c.counters.Inc(CounterClientFetched)
			e.token, e.issued, e.expires, e.err = tok, now, now.Add(ttl), nil
		}
		e.inflight = nil
		c.mu.Unlock()
		close(done)
	}()
	return done
}

// TokenError is a refused token request: the issuer's RFC 6749 error.
type TokenError struct {
	Status      int
	Code        string
	Description string
}

func (e *TokenError) Error() string {
	return fmt.Sprintf("token request refused (%d %s): %s", e.Status, e.Code, e.Description)
}

func (c *Client) fetch(ctx context.Context, audience string, scopes []string) (string, time.Duration, error) {
	form := url.Values{"grant_type": {GrantClientCredentials}, "scope": {strings.Join(scopes, " ")}, "audience": {audience}}
	if c.issuer != nil {
		a, err := c.issuer.Issue(c.cfg.ClientID, c.cfg.TokenURL, nil, assertionTTL, c.cfg.Now())
		if err != nil {
			return "", 0, err
		}
		form.Set("client_assertion_type", AssertionType)
		form.Set("client_assertion", a)
	} else {
		form.Set("client_id", c.cfg.ClientID)
		form.Set("client_secret", c.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxBodyBytes+1))
	if err != nil {
		return "", 0, fmt.Errorf("token response: %w", err)
	}
	if int64(len(body)) > c.cfg.MaxBodyBytes {
		return "", 0, fmt.Errorf("token response larger than %d bytes", c.cfg.MaxBodyBytes)
	}
	return ParseTokenResponse(resp.StatusCode, body)
}

// ParseTokenResponse reads an RFC 6749 §5.1 answer (or a §5.2 refusal)
// from an issuer: a Bearer token and a positive expires_in of at most
// MaxTokenTTL. The returned errors never contain the token.
func ParseTokenResponse(status int, body []byte) (string, time.Duration, error) {
	if status != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = "http_" + strconv.Itoa(status)
		}
		return "", 0, &TokenError{Status: status, Code: clip(e.Error), Description: clip(e.Description)}
	}
	var r struct {
		AccessToken string          `json:"access_token"`
		TokenType   string          `json:"token_type"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", 0, errors.New("token response is not a JSON object")
	}
	if r.AccessToken == "" || len(r.AccessToken) > auth.DefaultMaxTokenBytes {
		return "", 0, errors.New("token response has no usable access_token")
	}
	if !strings.EqualFold(r.TokenType, "Bearer") {
		return "", 0, errors.New("token response is not a Bearer token")
	}
	secs, err := strconv.ParseInt(string(r.ExpiresIn), 10, 64)
	if err != nil || secs <= 0 || secs > int64(MaxTokenTTL/time.Second) {
		return "", 0, errors.New("token response expires_in is not a positive integer of at most 3600")
	}
	return r.AccessToken, time.Duration(secs) * time.Second, nil
}
