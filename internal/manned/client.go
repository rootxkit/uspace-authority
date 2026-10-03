package manned

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Counters of the client (E-09).
const (
	CounterReconnects      = "reconnects"
	CounterConnected       = "connections_opened"
	CounterConnectFailed   = "connect_failed"
	CounterTokenRefused    = "token_unavailable" //nolint:gosec // a counter name, not a credential
	CounterSnapshotOK      = "snapshots_bootstrapped"
	CounterSnapshotFailed  = "snapshot_failed"
	CounterClosedBySwitch  = "closed_by_source_switch"
	CounterClosedSilent    = "closed_silent"
	CounterClosedByPeer    = "closed_by_peer"
	CounterBinaryFrames    = "binary_frames_skipped"
	CounterUnconfiguredRun = "not_connected_unconfigured"
)

// Tokens issues the ecosystem token the ANSP's routes take (scope
// ansp.traffic, aud the ANSP's host; internal/tokens.Client, M18).
type Tokens interface {
	Token(ctx context.Context, baseURL string, scopes ...string) (string, error)
}

// Client is the F4 client of the ANSP's manned traffic stream: for
// every connection it takes a token, bootstraps from GET
// /v1/manned-traffic/snapshot?bbox=, opens WS
// /v1/manned-traffic/stream?bbox= and hands every frame to the ingest.
// It reconnects forever with a jittered exponential backoff (B-08) and
// closes the stream when source control switches the feed off, opening
// it again when switched on. HTTP carries the TLS configuration: the
// client certificate when AUTHORITY_MTLS_MODE is required.
type Client struct {
	// BaseURL is the ANSP's published base URL; empty, nothing is
	// connected and the feed says ansp_unconfigured.
	BaseURL string
	// BBox is the bbox query parameter (west,south,east,north); empty
	// leaves it out.
	BBox   string
	Tokens Tokens
	HTTP   *http.Client
	Ingest *Ingest
	// Changes signals a source-control change.
	Changes <-chan struct{}
	// MaxSnapshotBytes bounds the snapshot read.
	MaxSnapshotBytes int64
	// RequestTimeout bounds the token, the snapshot and the upgrade.
	RequestTimeout time.Duration
	// SilentAfter closes a connection that carried no frame for this
	// long (the ANSP sends console/status/v1 every 2 s).
	SilentAfter time.Duration
	BackoffMin  time.Duration
	BackoffMax  time.Duration
	Counters    *core.Counters
	Logger      *slog.Logger
	Limiter     *logging.Limiter
	Now         func() time.Time
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) defaults() {
	if c.Counters == nil {
		c.Counters = &core.Counters{}
	}
	if c.Logger == nil {
		c.Logger = logging.Discard()
	}
	if c.Limiter == nil {
		c.Limiter = logging.NewLimiter(c.Logger, time.Minute, 0, c.Counters)
	}
	if c.HTTP == nil {
		c.HTTP = NoRedirectClient(nil)
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 5 * time.Second
	}
	if c.SilentAfter <= 0 {
		c.SilentAfter = 15 * time.Second
	}
	if c.BackoffMin <= 0 {
		c.BackoffMin = 500 * time.Millisecond
	}
	if c.BackoffMax < c.BackoffMin {
		c.BackoffMax = 30 * time.Second
	}
	if c.MaxSnapshotBytes <= 0 {
		c.MaxSnapshotBytes = 16 << 20
	}
}

// NoRedirectClient is an HTTP client on transport (http.DefaultTransport
// when nil) that follows no redirect: a bearer token never leaves for
// another host.
func NoRedirectClient(transport http.RoundTripper) *http.Client {
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// errSwitchedOff ends a session closed by source control.
var errSwitchedOff = errors.New("the feed was switched off by source control")

func (c *Client) feedOn() bool {
	g := c.Ingest.Gate
	if g == nil {
		return true
	}
	inst := c.Ingest.S.FeedInstance
	return g.Query(SourceType, &inst).Enabled
}

// endpoint is the URL of path on the ANSP with the bbox, in scheme.
func (c *Client) endpoint(path string, ws bool) (string, error) {
	u, err := url.Parse(strings.TrimSuffix(c.BaseURL, "/") + path)
	if err != nil || u.Host == "" {
		return "", core.Fieldf("ANSP_BASE_URL", "not an absolute URL")
	}
	if ws {
		switch u.Scheme {
		case "https":
			u.Scheme = "wss"
		case "http":
			u.Scheme = "ws"
		}
	}
	if c.BBox != "" {
		q := url.Values{}
		q.Set("bbox", c.BBox)
		u.RawQuery = q.Encode()
	}
	return u.String(), nil
}

// Run connects until ctx ends.
func (c *Client) Run(ctx context.Context) {
	c.defaults()
	in := c.Ingest
	in.init()
	if c.BaseURL == "" {
		in.Feed.Down(c.now(), ReasonUnconfigured)
		c.Counters.Inc(CounterUnconfiguredRun)
		<-ctx.Done()
		return
	}
	backoff := c.BackoffMin
	for ctx.Err() == nil {
		if !c.feedOn() {
			in.Feed.SetDisabled(true)
			in.Age("", StateSourceDisabled, c.now())
			select {
			case <-ctx.Done():
				return
			case <-c.Changes:
			}
			continue
		}
		in.Feed.SetDisabled(false)
		opened, err := c.session(ctx)
		if ctx.Err() != nil {
			return
		}
		if errors.Is(err, errSwitchedOff) {
			continue
		}
		if opened {
			backoff = c.BackoffMin
		}
		c.Counters.Inc(CounterReconnects)
		wait := backoff/2 + rand.N(backoff/2+1) //nolint:gosec // reconnection jitter, not a secret
		c.Limiter.Limited("manned_reconnect").Warn("ANSP manned traffic stream unavailable; reconnecting (data the ANSP holds is not lost)",
			slog.String("error", errString(err)), slog.Duration("retry_in", wait))
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		backoff = min(2*backoff, c.BackoffMax)
	}
}

func errString(err error) string {
	if err == nil {
		return "closed"
	}
	return truncate(err.Error(), 300)
}

// session is one connection: token, snapshot, stream. opened says the
// stream was open.
func (c *Client) session(ctx context.Context) (opened bool, err error) {
	in := c.Ingest
	if c.Tokens == nil {
		c.Counters.Inc(CounterTokenRefused)
		in.Feed.Down(c.now(), ReasonNoToken)
		return false, errors.New("no token client: every connection to the ANSP is refused locally")
	}
	tctx, cancel := context.WithTimeout(ctx, c.RequestTimeout)
	tok, err := c.Tokens.Token(tctx, c.BaseURL, Scope)
	cancel()
	if err != nil {
		c.Counters.Inc(CounterTokenRefused)
		in.Feed.Down(c.now(), ReasonNoToken)
		return false, fmt.Errorf("token for the ANSP: %w", err)
	}
	if err := c.snapshot(ctx, tok); err != nil {
		c.Counters.Inc(CounterSnapshotFailed)
		c.Limiter.Limited("manned_snapshot").Warn("ANSP snapshot not read; the stream's own snapshot bootstraps the picture",
			slog.String("error", errString(err)))
	}
	streamURL, err := c.endpoint(PathStream, true)
	if err != nil {
		return false, err
	}
	dctx, dcancel := context.WithTimeout(ctx, c.RequestTimeout)
	conn, resp, err := websocket.Dial(dctx, streamURL, &websocket.DialOptions{
		HTTPClient: c.HTTP, HTTPHeader: http.Header{"Authorization": {"Bearer " + tok}},
	})
	dcancel()
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		c.Counters.Inc(CounterConnectFailed)
		in.Feed.Down(c.now(), ReasonRefused)
		if resp != nil {
			return false, fmt.Errorf("stream upgrade refused with %d: %w", resp.StatusCode, err)
		}
		return false, fmt.Errorf("stream: %w", err)
	}
	defer func() { _ = conn.CloseNow() }()
	if in.S.MaxFrameBytes > 0 {
		conn.SetReadLimit(int64(in.S.MaxFrameBytes))
	}
	c.Counters.Inc(CounterConnected)
	in.Feed.Connected(c.now())
	c.Logger.Info("ANSP manned traffic stream open", slog.String("bbox", c.BBox))

	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	switched := make(chan struct{})
	go func() {
		for {
			select {
			case <-sctx.Done():
				return
			case <-c.Changes:
				if !c.feedOn() {
					close(switched)
					scancel()
					return
				}
			}
		}
	}()
	for {
		rctx, rcancel := context.WithTimeout(sctx, c.SilentAfter)
		typ, data, err := conn.Read(rctx)
		silent := errors.Is(rctx.Err(), context.DeadlineExceeded)
		rcancel()
		if err != nil {
			now := c.now()
			select {
			case <-switched:
				c.Counters.Inc(CounterClosedBySwitch)
				in.Feed.Down(now, ReasonClosed)
				in.Feed.SetDisabled(true)
				in.Age("", StateSourceDisabled, now)
				c.Logger.Warn("ANSP manned traffic stream closed: the feed was switched off by source control")
				return true, errSwitchedOff
			default:
			}
			if ctx.Err() != nil {
				_ = conn.Close(websocket.StatusGoingAway, "shutting down")
				in.Feed.Down(now, ReasonClosed)
				return true, ctx.Err()
			}
			reason := ReasonClosed
			if silent {
				reason = ReasonSilent
				c.Counters.Inc(CounterClosedSilent)
			} else {
				c.Counters.Inc(CounterClosedByPeer)
			}
			in.Feed.Down(now, reason)
			return true, err
		}
		if typ != websocket.MessageText {
			c.Counters.Inc(CounterBinaryFrames)
			continue
		}
		in.HandleFrame(data, c.now())
	}
}

// snapshot bootstraps from GET /v1/manned-traffic/snapshot?bbox=.
func (c *Client) snapshot(ctx context.Context, tok string) error {
	u, err := c.endpoint(PathSnapshot, false)
	if err != nil {
		return err
	}
	rctx, cancel := context.WithTimeout(ctx, c.RequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("snapshot answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.MaxSnapshotBytes+1))
	if err != nil {
		return err
	}
	if int64(len(body)) > c.MaxSnapshotBytes {
		return fmt.Errorf("snapshot longer than %d bytes", c.MaxSnapshotBytes)
	}
	c.Ingest.HandleSnapshot(body, c.now())
	c.Counters.Inc(CounterSnapshotOK)
	return nil
}
