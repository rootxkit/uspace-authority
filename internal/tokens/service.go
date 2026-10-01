package tokens

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
)

// MaxTokenTTL is table A's bound on a machine token.
const MaxTokenTTL = time.Hour

// GrantClientCredentials is the one grant type.
const GrantClientCredentials = "client_credentials"

// RFC 6749 §5.2 and RFC 8707 error codes.
const (
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidClient        = "invalid_client"
	ErrInvalidScope         = "invalid_scope"
	ErrInvalidTarget        = "invalid_target"
	ErrUnauthorizedClient   = "unauthorized_client" //nolint:misspell // RFC 6749 §5.2 error code
	ErrUnsupportedGrantType = "unsupported_grant_type"
	ErrTemporarily          = "temporarily_unavailable"
)

// Counters of the token service. Each refusal reason is also the
// reason in its token_refused event.
const (
	CounterIssued          = "tokens_issued"
	CounterRefused         = "tokens_refused"
	CounterRefusalNotSaved = "token_refusal_event_failed" // a refusal whose events row could not be written
)

// TokenRequest is a parsed /oauth/token form.
type TokenRequest struct {
	GrantType           string
	ClientID            string
	ClientSecret        string
	HasSecret           bool
	ClientAssertionType string
	ClientAssertion     string
	Scope               string
	Audience            string
	HasAudience         bool
	Resources           []string
	// RemoteIP is the caller's address, for the audit row.
	RemoteIP string
}

// TokenResponse is RFC 6749 §5.1.
type TokenResponse struct {
	AccessToken string
	ExpiresIn   int
	Scope       string
	// Claims kept for tests and the audit; never serialised.
	Issued   Issued
	Audience string
}

// OAuthError is a refused token request: the RFC 6749 error code, the
// HTTP status, a description for the client, and the internal reason
// recorded in the event and counted.
type OAuthError struct {
	Status      int
	Code        string
	Description string
	Reason      string
	RetryAfter  time.Duration
}

func (e *OAuthError) Error() string { return e.Code + ": " + e.Description }

func refuse(status int, code, reason, description string) *OAuthError {
	return &OAuthError{Status: status, Code: code, Reason: reason, Description: description}
}

// ServiceConfig configures a Service.
type ServiceConfig struct {
	// TokenEndpoint is the issuer's /oauth/token URL: an accepted aud of
	// client assertions, beside the issuer itself.
	TokenEndpoint string
	TTL           time.Duration
	Now           func() time.Time
}

// Service issues ecosystem machine tokens (client credentials).
type Service struct {
	Store    Store
	Keys     *Keys
	Hasher   *passhash.Hasher
	Limiter  *httpx.RateLimiter // per authenticated client
	Replay   *ReplayMemory
	Counters *core.Counters
	Logger   *slog.Logger
	Config   ServiceConfig
}

func (s *Service) now() time.Time {
	if s.Config.Now != nil {
		return s.Config.Now()
	}
	return time.Now()
}

func (s *Service) ttl() time.Duration {
	if s.Config.TTL <= 0 || s.Config.TTL > MaxTokenTTL {
		return MaxTokenTTL
	}
	return s.Config.TTL
}

func (s *Service) count(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

// Token runs the client credentials grant. Every outcome is an events
// row: token_issued in the transaction that returns the token (no row,
// no token), token_refused in a transaction of its own.
func (s *Service) Token(ctx context.Context, req TokenRequest) (TokenResponse, *OAuthError) {
	now := s.now()
	client, oerr := s.authenticate(ctx, req, now)
	if oerr == nil {
		oerr = s.allowRate(client.ID)
	}
	var scopes []string
	var aud string
	if oerr == nil {
		scopes, aud, oerr = s.authorise(client, req)
	}
	if oerr != nil {
		s.recordRefusal(ctx, req, client.ID, oerr)
		return TokenResponse{}, oerr
	}
	issued, err := s.Keys.Issue(client.ID, aud, scopes, s.ttl(), now)
	if err != nil {
		logging.Error(ctx, s.logger(), "token signing failed", err, slog.String("client_id", client.ID))
		return TokenResponse{}, refuse(http.StatusInternalServerError, ErrTemporarily, "signing_failed", "the token could not be signed")
	}
	err = s.Store.InTx(ctx, func(tx Tx) error {
		return tx.Record(ctx, audit.Event{
			Actor: audit.Actor{Type: audit.ActorClient, ID: client.ID}, EntityType: "oauth_client", EntityID: client.ID,
			EventType: audit.EventTokenIssued,
			Payload: map[string]any{
				"jti": issued.JTI, "kid": issued.KID, "aud": aud, "scopes": scopes,
				"iat": issued.IssuedAt, "exp": issued.ExpiresAt, "remote_ip": req.RemoteIP,
			},
		})
	})
	if err != nil {
		// No audit row, no token (06 §3).
		logging.Error(ctx, s.logger(), "token issued but not audited; withheld", err, slog.String("client_id", client.ID))
		return TokenResponse{}, refuse(http.StatusInternalServerError, ErrTemporarily, "audit_failed", "the issuance could not be recorded")
	}
	s.count(CounterIssued)
	return TokenResponse{
		AccessToken: issued.Token, ExpiresIn: int(issued.ExpiresAt.Sub(issued.IssuedAt).Seconds()),
		Scope: strings.Join(scopes, " "), Issued: issued, Audience: aud,
	}, nil
}

// authenticate finds the client and checks its credential. An unknown
// client and a wrong secret take the same work and give the same answer.
func (s *Service) authenticate(ctx context.Context, req TokenRequest, now time.Time) (Client, *OAuthError) {
	if req.GrantType != GrantClientCredentials {
		if req.GrantType == "" {
			return Client{}, refuse(http.StatusBadRequest, ErrInvalidRequest, "grant_type_missing", "grant_type is required")
		}
		return Client{}, refuse(http.StatusBadRequest, ErrUnsupportedGrantType, "grant_type_unsupported", "only client_credentials is supported")
	}
	hasAssertion := req.ClientAssertion != "" || req.ClientAssertionType != ""
	switch {
	case hasAssertion && req.HasSecret:
		return Client{}, refuse(http.StatusBadRequest, ErrInvalidRequest, "two_client_credentials", "use one client authentication method")
	case hasAssertion:
		return s.authenticateAssertion(ctx, req, now)
	case req.ClientID == "" || !req.HasSecret:
		return Client{}, refuse(http.StatusUnauthorized, ErrInvalidClient, "client_credentials_missing",
			"client_id with client_secret, or a client assertion, is required (client_secret_basic is not supported)")
	}
	invalid := refuse(http.StatusUnauthorized, ErrInvalidClient, "client_authentication_failed", "client authentication failed")
	c, err := s.Store.Client(ctx, req.ClientID)
	if err != nil {
		s.Hasher.VerifyDummy(req.ClientSecret)
		if !errors.Is(err, ErrNotFound) {
			logging.Error(ctx, s.logger(), "client lookup failed", err)
			return Client{}, refuse(http.StatusInternalServerError, ErrTemporarily, "store_failed", "the client registry is unavailable")
		}
		invalid.Reason = "client_unknown"
		return Client{}, invalid
	}
	if c.AuthMethod != MethodSecretPost || c.SecretHash == "" {
		s.Hasher.VerifyDummy(req.ClientSecret)
		invalid.Reason = "client_auth_method_mismatch"
		return Client{}, invalid
	}
	ok, err := s.Hasher.Verify(req.ClientSecret, c.SecretHash)
	if err != nil || !ok {
		invalid.Reason = "client_secret_wrong"
		return Client{}, invalid
	}
	return c, s.checkStatus(c)
}

func (s *Service) authenticateAssertion(ctx context.Context, req TokenRequest, now time.Time) (Client, *OAuthError) {
	invalid := refuse(http.StatusUnauthorized, ErrInvalidClient, "client_assertion_invalid", "the client assertion was not accepted")
	if req.ClientAssertionType != AssertionType {
		return Client{}, refuse(http.StatusBadRequest, ErrInvalidRequest, "client_assertion_type_wrong",
			"client_assertion_type must be "+AssertionType)
	}
	id := UnverifiedIssuer(req.ClientAssertion)
	if id == "" {
		return Client{}, invalid
	}
	if req.ClientID != "" && req.ClientID != id {
		return Client{}, refuse(http.StatusBadRequest, ErrInvalidRequest, "client_id_mismatch", "client_id differs from the assertion's issuer")
	}
	c, err := s.Store.Client(ctx, id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			logging.Error(ctx, s.logger(), "client lookup failed", err)
			return Client{}, refuse(http.StatusInternalServerError, ErrTemporarily, "store_failed", "the client registry is unavailable")
		}
		invalid.Reason = "client_unknown"
		return Client{}, invalid
	}
	if c.AuthMethod != MethodPrivateKeyJWT {
		invalid.Reason = "client_auth_method_mismatch"
		return Client{}, invalid
	}
	iss := s.Keys.Issuer()
	jti, exp, err := VerifyAssertion(ctx, c, req.ClientAssertion, []string{iss, s.Config.TokenEndpoint}, now)
	if err != nil {
		var te *auth.TokenError
		if errors.As(err, &te) {
			invalid.Reason = "client_assertion_" + te.Counter
		}
		return Client{}, invalid
	}
	if err := s.Replay.Use(c.ID, jti, exp, now); err != nil {
		if errors.Is(err, ErrReplayFull) {
			return Client{}, refuse(http.StatusServiceUnavailable, ErrTemporarily, "assertion_replay_memory_full", "try again shortly")
		}
		invalid.Reason = "client_assertion_replayed"
		return Client{}, invalid
	}
	return c, s.checkStatus(c)
}

func (s *Service) checkStatus(c Client) *OAuthError {
	if c.Status != StatusActive {
		return refuse(http.StatusUnauthorized, ErrInvalidClient, "client_"+c.Status, "the client is "+c.Status)
	}
	return nil
}

func (s *Service) allowRate(clientID string) *OAuthError {
	if s.Limiter == nil {
		return nil
	}
	ok, wait := s.Limiter.Allow(clientID)
	if ok {
		return nil
	}
	e := refuse(http.StatusTooManyRequests, ErrTemporarily, "rate_limited", "the client's token budget is spent")
	e.RetryAfter = wait
	return e
}

// authorise checks the requested scopes and audience against table B and
// the client's registration.
func (s *Service) authorise(c Client, req TokenRequest) ([]string, string, *OAuthError) {
	scopes, err := ParseScopeParam(req.Scope)
	if err != nil {
		return nil, "", refuse(http.StatusBadRequest, ErrInvalidScope, "scope_malformed", err.Error())
	}
	if len(scopes) == 0 {
		return nil, "", refuse(http.StatusBadRequest, ErrInvalidScope, ReasonScopeMissing, "scope is required: name the catalogue scopes the token needs")
	}
	for _, sc := range scopes {
		if err := CheckGrantable(sc, c.ID); err != nil {
			var se *ScopeError
			reason := ReasonScopeUnknown
			if errors.As(err, &se) {
				reason = se.Reason
			}
			return nil, "", refuse(http.StatusBadRequest, ErrInvalidScope, reason, err.Error())
		}
		if !slices.Contains(c.Scopes, sc) {
			return nil, "", refuse(http.StatusBadRequest, ErrInvalidScope, ReasonScopeNotAllowed,
				(&ScopeError{Scope: sc, Reason: ReasonScopeNotAllowed}).Error())
		}
	}
	targets := slices.Clone(req.Resources)
	if req.HasAudience {
		targets = append(targets, req.Audience)
	}
	if len(targets) == 0 {
		return nil, "", refuse(http.StatusBadRequest, ErrInvalidTarget, ReasonAudienceMissing,
			"audience (or one resource) is required: the host of the target's base URL")
	}
	aud, err := NormalizeAudience(targets[0])
	if err != nil {
		return nil, "", refuse(http.StatusBadRequest, ErrInvalidTarget, ReasonAudienceInvalid, err.Error())
	}
	for _, t := range targets[1:] {
		if h, err := NormalizeAudience(t); err != nil || h != aud {
			return nil, "", refuse(http.StatusBadRequest, ErrInvalidTarget, ReasonAudienceMultiple, "one audience per token; request one token per target")
		}
	}
	if HasNational(scopes) && !slices.Contains(c.Audiences, aud) {
		return nil, "", refuse(http.StatusBadRequest, ErrInvalidTarget, ReasonAudienceNotAllowed,
			quote(aud)+" is not on this client's audience list (national scopes)")
	}
	return scopes, aud, nil
}

// recordRefusal writes the token_refused row in its own transaction, so
// the refusal is recorded although the request fails. A failure to
// record is counted and logged; the refusal stands.
func (s *Service) recordRefusal(ctx context.Context, req TokenRequest, clientID string, oerr *OAuthError) {
	s.count(CounterRefused)
	actorID := clientID
	if actorID == "" {
		actorID = clip(req.ClientID)
	}
	if actorID == "" {
		actorID = "unknown"
	}
	payload := map[string]any{
		"error": oerr.Code, "reason": oerr.Reason, "client_id": clip(req.ClientID), "authenticated": clientID != "",
		"scope": clip(req.Scope), "audience": clip(req.Audience), "remote_ip": req.RemoteIP,
	}
	err := s.Store.InTx(ctx, func(tx Tx) error {
		return tx.Record(ctx, audit.Event{
			Actor: audit.Actor{Type: audit.ActorClient, ID: actorID}, EntityType: "oauth_client", EntityID: actorID,
			EventType: audit.EventTokenRefused, Payload: payload,
		})
	})
	if err != nil {
		s.count(CounterRefusalNotSaved)
		logging.Error(ctx, s.logger(), "token refusal not recorded", err, slog.String("reason", oerr.Reason))
	}
}

// clip bounds a request value before it is stored: valid UTF-8, at most
// 128 bytes.
func clip(v string) string {
	v = strings.ToValidUTF8(v, "?")
	if len(v) > 128 {
		v = v[:128]
		for len(v) > 0 && !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}
