package picture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// The session contract (M21, M22; docs/runbooks/session-contract.md).
const (
	CookieSession = "uspace_session"
	RealmConsole  = "console"
	RealmPolice   = "police"
)

// Counter names of the session checks (E-09).
const (
	CounterSessionAccepted      = "session_accepted"
	CounterSessionRefused       = "session_refused"
	CounterSessionUnavailable   = "session_unavailable"
	CounterVerifierNotReady     = "session_verifier_not_ready"
	CounterVerifierFetchFailed  = "session_verifier_jwks_unavailable"
	CounterSessionCheckFailed   = "session_check_failed"
	CounterSessionRevokedClosed = "session_revoked_closed"
	CounterSessionGraceClosed   = "session_grace_closed"
)

// ErrRefused marks a session that is not one: no token, a token core's
// verifier refuses, a machine token, an unknown realm, or a session row
// api says is not live (logged out, revoked, expired, idle). The console
// signs in again (4401).
var ErrRefused = errors.New("session refused")

// ErrUnavailable marks a check that could not be made: the verifier has
// no keys yet or api did not answer. Nothing is admitted on it (routes
// fail closed); a live connection is kept for PICTURE_SESSION_GRACE_S.
var ErrUnavailable = errors.New("session check unavailable")

func refused(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, args...))
}

// Session is a checked console session.
type Session struct {
	Subject   string
	JTI       string
	Realm     string
	Roles     []string
	ExpiresAt time.Time
}

// Console reports whether the session is of the console realm: only it
// sees a Display Provider flight's remote pilot position (06 §5).
func (s Session) Console() bool { return s.Realm == RealmConsole }

// Checker checks a session token: a Session, or an error wrapping
// ErrRefused or ErrUnavailable.
type Checker interface {
	Check(ctx context.Context, token string) (Session, error)
}

// TokenVerifier is core's auth.Verifier (or LazyVerifier).
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (auth.Claims, error)
}

// maxSessionBody bounds what is read of api's answer.
const maxSessionBody = 64 << 10

// APIChecker is the session check of picture-ws: the token is verified
// by uspace-core's verifier (RS256, this issuer, the audiences,
// StrictSessionClaims) and must be a session (scope "session" alone,
// realm console or police, a jti); then api's GET /v1/auth/session is
// asked, with the token as bearer, whether its sessions row is live.
// picture-ws never opens the relational database (B-15, CLAUDE.md rule
// 10): the sessions table is api's, so a logout, a revocation, a disable
// and the idle expiry end a stream exactly as they end every api call.
type APIChecker struct {
	Verifier TokenVerifier
	// URL is api's GET /v1/auth/session (PICTURE_SESSION_URL).
	URL      string
	Client   *http.Client
	Timeout  time.Duration
	Counters *core.Counters
}

func (c *APIChecker) inc(name string) {
	if c.Counters != nil {
		c.Counters.Inc(name)
	}
}

// sessionInfo is api's SessionInfo (api/openapi.yaml).
type sessionInfo struct {
	Sub       string    `json:"sub"`
	Roles     []string  `json:"roles"`
	Realm     string    `json:"realm"`
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Check implements Checker. The error never contains the token.
func (c *APIChecker) Check(ctx context.Context, token string) (Session, error) {
	s, err := c.check(ctx, token)
	switch {
	case err == nil:
		c.inc(CounterSessionAccepted)
	case errors.Is(err, ErrRefused):
		c.inc(CounterSessionRefused)
	default:
		c.inc(CounterSessionUnavailable)
	}
	return s, err
}

func (c *APIChecker) check(ctx context.Context, token string) (Session, error) {
	if strings.TrimSpace(token) == "" {
		return Session{}, refused("no session token")
	}
	cl, err := c.Verifier.Verify(ctx, token)
	if err != nil {
		var te *auth.TokenError
		if errors.As(err, &te) {
			return Session{}, refused("token refused: %s", te.Error())
		}
		return Session{}, unavailable("token not verified: %v", err)
	}
	switch {
	case len(cl.Scopes) != 1 || cl.Scopes[0] != auth.SessionScope:
		return Session{}, refused("the token's scope is not \"session\" alone: a machine token is not a session")
	case cl.Realm != RealmConsole && cl.Realm != RealmPolice:
		return Session{}, refused("unknown realm %q", cl.Realm)
	case cl.JTI == "":
		return Session{}, refused("a session without a jti")
	}
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, http.NoBody) //nolint:gosec // the URL is the operator's configuration (PICTURE_SESSION_URL)
	if err != nil {
		return Session{}, unavailable("session check request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req) //nolint:gosec // to PICTURE_SESSION_URL only; redirects are never followed
	if err != nil {
		c.inc(CounterSessionCheckFailed)
		return Session{}, unavailable("api did not answer the session check")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSessionBody))
	if err != nil {
		c.inc(CounterSessionCheckFailed)
		return Session{}, unavailable("api's answer to the session check was cut")
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Session{}, refused("api: %s", problemDetail(body, resp.StatusCode))
	default:
		c.inc(CounterSessionCheckFailed)
		return Session{}, unavailable("api answered the session check with %d", resp.StatusCode)
	}
	var si sessionInfo
	if err := json.Unmarshal(body, &si); err != nil {
		c.inc(CounterSessionCheckFailed)
		return Session{}, unavailable("api's session answer does not decode")
	}
	if si.JTI != cl.JTI || si.Sub != cl.Subject || si.Realm != cl.Realm {
		return Session{}, refused("api's session row is not this token's")
	}
	return Session{Subject: si.Sub, JTI: si.JTI, Realm: si.Realm, Roles: slices.Clone(si.Roles), ExpiresAt: cl.ExpiresAt}, nil
}

func (c *APIChecker) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return NoRedirectClient()
}

// NoRedirectClient is the HTTP client of the session check: a redirect
// is never followed, so the bearer never leaves for another host.
func NoRedirectClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// problemDetail is the detail of a problem+json body, bounded, or the
// status.
func problemDetail(body []byte, status int) string {
	var p struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &p) == nil && p.Detail != "" {
		if len(p.Detail) > 200 {
			return p.Detail[:200]
		}
		return p.Detail
	}
	return fmt.Sprintf("status %d", status)
}

// errVerifierNotReady is LazyVerifier's answer until the issuer's keys
// were fetched once.
var errVerifierNotReady = errors.New("this issuer's JWKS has not been fetched yet")

// LazyVerifier is core's auth.Verifier for this issuer, built in the
// background when the JWKS cannot be fetched at start, so picture-ws
// starts (and serves its status) with api down; until it is built every
// session is refused as unavailable (fail closed). Counters aggregates
// the verdicts by core's counter names.
type LazyVerifier struct {
	Config     auth.Config
	RetryEvery time.Duration
	Logger     *slog.Logger

	v        atomic.Pointer[auth.Verifier]
	counters core.Counters
}

// Start tries to build the verifier once within the fetch timeout and,
// when that fails, keeps trying every RetryEvery until ctx ends.
func (l *LazyVerifier) Start(ctx context.Context) {
	if l.try(ctx) {
		return
	}
	every := l.RetryEvery
	if every <= 0 {
		every = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if l.try(ctx) {
					return
				}
			}
		}
	}()
}

func (l *LazyVerifier) try(ctx context.Context) bool {
	fctx, cancel := context.WithTimeout(ctx, auth.DefaultJWKSFetchTimeout+time.Second)
	defer cancel()
	v, err := auth.NewVerifier(fctx, l.Config)
	if err != nil {
		l.counters.Inc(CounterVerifierFetchFailed)
		logger := l.Logger
		if logger == nil {
			logger = logging.Discard()
		}
		logger.Warn("session verifier not ready: every console is refused until this issuer's JWKS is fetched",
			slog.String("error", err.Error()))
		return false
	}
	l.v.Store(v)
	return true
}

// Ready reports whether the verifier has keys.
func (l *LazyVerifier) Ready() bool { return l.v.Load() != nil }

// Verify implements TokenVerifier.
func (l *LazyVerifier) Verify(ctx context.Context, token string) (auth.Claims, error) {
	v := l.v.Load()
	if v == nil {
		l.counters.Inc(CounterVerifierNotReady)
		return auth.Claims{}, errVerifierNotReady
	}
	cl, err := v.Verify(ctx, token)
	if err != nil {
		var te *auth.TokenError
		if errors.As(err, &te) {
			l.counters.Inc(te.Counter)
		}
		return auth.Claims{}, err
	}
	l.counters.Inc(auth.CounterAccepted)
	return cl, nil
}

// Counters are the verdicts and the fetch failures.
func (l *LazyVerifier) Counters() *core.Counters { return &l.counters }
