package authz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/pii"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// Problem slugs of the sign-in refusals.
const (
	SlugInvalidCredentials = "invalid_credentials" //nolint:gosec // a problem slug, not a credential
	SlugMFARefused         = "mfa_refused"
	SlugSessionRefused     = "session_refused"
)

// Counters of the accounts service.
const (
	CounterLoginAccepted     = "login_password_accepted"
	CounterLoginRefused      = "login_refused"
	CounterMFARefused        = "mfa_refused"
	CounterSessionsStarted   = "sessions_started"
	CounterSessionsSwept     = "sessions_swept"
	CounterRefusalNotSaved   = "auth_refusal_event_failed" // a refusal whose events row could not be written
	CounterBootstrapRefused  = "user_bootstrap_refused"
	CounterSessionIdleEnded  = "sessions_idle_ended"
	CounterSessionLimitEnded = "sessions_limit_ended"
	CounterMFALocked         = "mfa_accounts_locked"
)

// Config are the account and session settings (config.Auth).
type Config struct {
	// OwnHost is the aud of every session (M20: the system's own host).
	OwnHost        string
	SessionTTL     time.Duration
	IdleTimeout    time.Duration
	MaxSessions    int
	ChallengeTTL   time.Duration
	MaxAttempts    int
	PasswordMinLen int
	TOTPIssuer     string
	// The per-account MFA failure budget (NIST SP 800-63B 5.2.2):
	// LockoutAfter failures lock the account for LockoutBase, doubling
	// with each further failure up to LockoutMax; HardLockAfter failures
	// lock it until an admin unlocks it. Zero LockoutAfter disables it
	// (tests only; the configuration requires it).
	LockoutAfter  int
	LockoutBase   time.Duration
	LockoutMax    time.Duration
	HardLockAfter int
	Now           func() time.Time
}

// Service is console accounts, sign-in and sessions.
type Service struct {
	Store       Store
	Hasher      *passhash.Hasher
	Sealer      *pii.Sealer
	Keys        *tokens.Keys
	IPLimiter   *httpx.RateLimiter
	UserLimiter *httpx.RateLimiter
	Counters    *core.Counters
	Logger      *slog.Logger
	Config      Config
}

func (s *Service) now() time.Time {
	if s.Config.Now != nil {
		return s.Config.Now()
	}
	return time.Now()
}

func (s *Service) count(name string) {
	if s.Counters != nil {
		s.Counters.Inc(name)
	}
}

func (s *Service) logger() *slog.Logger {
	if s.Logger == nil {
		return logging.Discard()
	}
	return s.Logger
}

// RateLimitedError is a refusal for a spent budget, answered 429 with
// Retry-After.
type RateLimitedError struct {
	Problem    *httpx.Problem
	RetryAfter time.Duration
}

func (e *RateLimitedError) Error() string { return "rate_limited: " + e.Problem.Detail }

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]{2,63}$`)

// NormalizeUsername is the stored form of a username: trimmed and
// lower-case.
func NormalizeUsername(raw string) string { return strings.ToLower(strings.TrimSpace(raw)) }

// limiterKey bounds what keys a limiter: a username that is not valid is
// still limited, under its clipped form.
func limiterKey(username string) string {
	if len(username) > 64 {
		username = username[:64]
	}
	return "u:" + strings.ToValidUTF8(username, "?")
}

func invalidCredentials() error {
	return httpx.Refuse(http.StatusUnauthorized, SlugInvalidCredentials, "the username or the password is wrong")
}

// LoginResult is the first step's answer.
type LoginResult struct {
	Token     string
	ExpiresAt time.Time
	// EnrolSecret and EnrolURI are set while the account has no
	// confirmed TOTP.
	EnrolSecret string
	EnrolURI    string
}

// Login checks a password and opens an MFA challenge. Unknown user,
// disabled user and wrong password are one answer after one argon2id
// verification each; every attempt is an events row.
func (s *Service) Login(ctx context.Context, username, password string, ri apiserver.RequestInfo) (LoginResult, error) {
	now := s.now()
	norm := NormalizeUsername(username)
	if s.IPLimiter != nil {
		if ok, wait := s.IPLimiter.Allow("ip:" + ri.RemoteIP); !ok {
			return LoginResult{}, s.limited(ctx, norm, ri, "rate_limited_address", wait)
		}
	}
	if s.UserLimiter != nil {
		if ok, wait := s.UserLimiter.Allow(limiterKey(norm)); !ok {
			return LoginResult{}, s.limited(ctx, norm, ri, "rate_limited_username", wait)
		}
	}
	u, err := s.Store.UserByUsername(ctx, norm)
	if err != nil {
		s.Hasher.VerifyDummy(password)
		if !errors.Is(err, ErrNotFound) {
			return LoginResult{}, fmt.Errorf("read account: %w", err)
		}
		s.refuseLogin(ctx, "", norm, ri, "unknown_user")
		return LoginResult{}, invalidCredentials()
	}
	hash, err := s.Store.PasswordHash(ctx, u.ID)
	if err != nil {
		s.Hasher.VerifyDummy(password)
		if !errors.Is(err, ErrNotFound) {
			return LoginResult{}, fmt.Errorf("read credential: %w", err)
		}
		s.refuseLogin(ctx, u.ID, norm, ri, "no_password")
		return LoginResult{}, invalidCredentials()
	}
	ok, err := s.Hasher.Verify(password, hash)
	if err != nil || !ok {
		s.refuseLogin(ctx, u.ID, norm, ri, "wrong_password")
		return LoginResult{}, invalidCredentials()
	}
	if u.Status != StatusActive {
		s.refuseLogin(ctx, u.ID, norm, ri, "user_disabled")
		return LoginResult{}, invalidCredentials()
	}

	var out LoginResult
	err = s.Store.InTx(ctx, func(tx Tx) error {
		if s.Hasher.NeedsRehash(hash) {
			nh, err := s.Hasher.Hash(password)
			if err != nil {
				return err
			}
			if err := tx.SetPassword(ctx, u.ID, nh, now); err != nil {
				return err
			}
		}
		m, err := tx.MFA(ctx, u.ID)
		switch {
		case errors.Is(err, ErrNotFound):
			secret, uri, err := NewTOTPSecret(s.Config.TOTPIssuer, u.Username)
			if err != nil {
				return err
			}
			sealed, err := s.Sealer.Seal([]byte(secret), mfaAAD(u.ID))
			if err != nil {
				return err
			}
			if err := tx.SaveMFA(ctx, MFA{UserID: u.ID, KeyID: s.Sealer.KeyID(), SecretEnc: sealed}, now); err != nil {
				return err
			}
			out.EnrolSecret, out.EnrolURI = secret, uri
		case err != nil:
			return err
		case m.EnrolledAt == nil:
			secret, err := s.Sealer.Open(m.KeyID, m.SecretEnc, mfaAAD(u.ID))
			if err != nil {
				return err
			}
			out.EnrolSecret = string(secret)
			if out.EnrolURI, err = TOTPURI(s.Config.TOTPIssuer, u.Username, out.EnrolSecret); err != nil {
				return err
			}
		}
		token, hash, err := newChallengeToken()
		if err != nil {
			return err
		}
		out.Token, out.ExpiresAt = token, now.Add(s.Config.ChallengeTTL)
		if err := tx.InsertChallenge(ctx, Challenge{TokenHash: hash, UserID: u.ID, CreatedAt: now, ExpiresAt: out.ExpiresAt, RemoteIP: ri.RemoteIP}); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: userActor(u), EntityType: "user", EntityID: u.ID, EventType: audit.EventLoginPasswordAccepted,
			Payload: map[string]any{"username": u.Username, "enrolment_pending": out.EnrolSecret != "", "remote_ip": ri.RemoteIP},
		})
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("open challenge: %w", err)
	}
	s.count(CounterLoginAccepted)
	return out, nil
}

func mfaAAD(userID string) []byte { return []byte("user_mfa:" + userID) }

// newChallengeToken is 256 random bits, base64url, and its SHA-256 hex:
// only the hash is stored.
func newChallengeToken() (token, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b[:])
	return token, hashToken(token), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func userActor(u User) audit.Actor {
	return audit.Actor{Type: audit.ActorUser, ID: u.ID, Realm: u.Realm}
}

// anonymous is the actor of a refusal whose account is unknown.
var anonymous = audit.Actor{Type: audit.ActorUser, ID: "unknown"}

func (s *Service) limited(ctx context.Context, username string, ri apiserver.RequestInfo, reason string, wait time.Duration) error {
	s.refuseLogin(ctx, "", username, ri, reason)
	return &RateLimitedError{
		Problem:    httpx.NewProblem(http.StatusTooManyRequests, httpx.SlugRateLimited, "Too many requests", "too many sign-in attempts; wait and try again"),
		RetryAfter: wait,
	}
}

// refuseLogin records login_refused in its own transaction; a failure to
// record is counted and logged, and the refusal stands.
func (s *Service) refuseLogin(ctx context.Context, userID, username string, ri apiserver.RequestInfo, reason string) {
	s.count(CounterLoginRefused)
	actor := anonymous
	if userID != "" {
		actor = audit.Actor{Type: audit.ActorUser, ID: userID}
	}
	s.recordOwnTx(ctx, audit.Event{
		Actor: actor, EntityType: "user", EntityID: actor.ID, EventType: audit.EventLoginRefused,
		Payload: map[string]any{"username": clip(username), "reason": reason, "remote_ip": ri.RemoteIP},
	})
}

func (s *Service) recordOwnTx(ctx context.Context, ev audit.Event) {
	err := s.Store.InTx(ctx, func(tx Tx) error { return tx.Record(ctx, ev) })
	if err != nil {
		s.count(CounterRefusalNotSaved)
		logging.Error(ctx, s.logger(), "refusal not recorded", err, slog.String("event_type", ev.EventType))
	}
}

// clip bounds a value from a request before it is stored.
func clip(v string) string {
	v = strings.ToValidUTF8(v, "?")
	for len(v) > 128 {
		v = v[:128]
		for len(v) > 0 && !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

// MFAResult is the second step's answer: a session.
type MFAResult struct {
	Token   string
	Session Session
	// RecoveryCodes are set at the sign-in that confirms enrolment.
	RecoveryCodes []string
}

func mfaRefused(detail string) error {
	return httpx.Refuse(http.StatusUnauthorized, SlugMFARefused, detail)
}

// VerifyMFA exchanges a challenge and a TOTP code, or a recovery code,
// for a session (table A). Refusals are mfa_refused events committed on
// their own; the session is a session_started event in the transaction
// that creates it.
func (s *Service) VerifyMFA(ctx context.Context, challenge, code, recovery string, ri apiserver.RequestInfo) (MFAResult, error) {
	now := s.now()
	if s.IPLimiter != nil {
		if ok, wait := s.IPLimiter.Allow("ip:" + ri.RemoteIP); !ok {
			s.refuseMFA(ctx, anonymous, ri, "rate_limited_address")
			return MFAResult{}, &RateLimitedError{
				Problem:    httpx.NewProblem(http.StatusTooManyRequests, httpx.SlugRateLimited, "Too many requests", "too many sign-in attempts; wait and try again"),
				RetryAfter: wait,
			}
		}
	}
	if challenge == "" || len(challenge) > 256 || (code == "") == (recovery == "") {
		s.refuseMFA(ctx, anonymous, ri, "malformed")
		return MFAResult{}, mfaRefused("send the challenge with either a code or a recovery code")
	}
	var out MFAResult
	var refusal error
	err := s.Store.InTx(ctx, func(tx Tx) error {
		refuse := func(actor audit.Actor, reason, detail string) error {
			s.count(CounterMFARefused)
			refusal = mfaRefused(detail)
			return tx.Record(ctx, audit.Event{
				Actor: actor, EntityType: "user", EntityID: actor.ID, EventType: audit.EventMFARefused,
				Payload: map[string]any{"reason": reason, "remote_ip": ri.RemoteIP},
			})
		}
		ch, err := tx.ChallengeForUpdate(ctx, hashToken(challenge))
		if errors.Is(err, ErrNotFound) {
			return refuse(anonymous, "challenge_unknown", "the challenge is not valid; sign in again")
		}
		if err != nil {
			return err
		}
		actor := audit.Actor{Type: audit.ActorUser, ID: ch.UserID}
		switch {
		case ch.UsedAt != nil:
			return refuse(actor, "challenge_used", "the challenge was used; sign in again")
		case !now.Before(ch.ExpiresAt):
			return refuse(actor, "challenge_expired", "the challenge expired; sign in again")
		case ch.Attempts >= s.Config.MaxAttempts:
			return refuse(actor, "challenge_exhausted", "too many wrong codes; sign in again")
		}
		u, err := tx.UserForUpdate(ctx, ch.UserID)
		if err != nil {
			return err
		}
		actor = userActor(u)
		if u.Status != StatusActive {
			return refuse(actor, "user_disabled", "the challenge is not valid; sign in again")
		}
		if u.MFAHardLocked {
			return refuse(actor, "mfa_locked_until_unlocked", "too many wrong codes: an admin must unlock this account")
		}
		if u.MFALockedUntil != nil && now.Before(*u.MFALockedUntil) {
			return refuse(actor, "mfa_locked", "too many wrong codes: try again after "+u.MFALockedUntil.UTC().Format(time.RFC3339))
		}
		m, err := tx.MFA(ctx, u.ID)
		if errors.Is(err, ErrNotFound) {
			return refuse(actor, "mfa_reset", "the challenge is not valid; sign in again")
		}
		if err != nil {
			return err
		}
		accepted, reason := false, "wrong_code"
		if recovery != "" {
			if m.EnrolledAt == nil {
				reason = "recovery_before_enrolment"
			} else if i := MatchRecoveryCode(recovery, m.RecoveryHashes); i >= 0 {
				m.RecoveryHashes = slices.Delete(slices.Clone(m.RecoveryHashes), i, i+1)
				accepted = true
			} else {
				reason = "wrong_recovery_code"
			}
		} else {
			secret, err := s.Sealer.Open(m.KeyID, m.SecretEnc, mfaAAD(u.ID))
			if err != nil {
				return err
			}
			if step, ok := VerifyTOTP(string(secret), code, now, m.LastStep); ok {
				m.LastStep, accepted = step, true
			}
		}
		if !accepted {
			if err := tx.CountChallengeAttempt(ctx, ch.TokenHash); err != nil {
				return err
			}
			if err := s.countMFAFailure(ctx, tx, u, now); err != nil {
				return err
			}
			return refuse(actor, reason, "the code is wrong")
		}
		if u.MFAFailures > 0 || u.MFALockedUntil != nil {
			if err := tx.SetMFALock(ctx, u.ID, MFALock{}); err != nil {
				return err
			}
		}
		if err := tx.UseChallenge(ctx, ch.TokenHash, now); err != nil {
			return err
		}
		if m.EnrolledAt == nil {
			codes, hashes, err := NewRecoveryCodes(RecoveryCodes)
			if err != nil {
				return err
			}
			m.EnrolledAt, m.RecoveryHashes, out.RecoveryCodes = &now, hashes, codes
			if err := tx.Record(ctx, audit.Event{
				Actor: actor, EntityType: "user", EntityID: u.ID, EventType: audit.EventMFAEnrolled,
				Payload: map[string]any{"recovery_codes": len(codes)},
			}); err != nil {
				return err
			}
		}
		if err := tx.SaveMFA(ctx, m, now); err != nil {
			return err
		}
		out.Token, out.Session, err = s.startSession(ctx, tx, u, ri, recovery != "", now)
		return err
	})
	if err != nil {
		return MFAResult{}, fmt.Errorf("verify MFA: %w", err)
	}
	if refusal != nil {
		return MFAResult{}, refusal
	}
	s.count(CounterSessionsStarted)
	return out, nil
}

// LockFor is the timed lock after failures (at least LockoutAfter): the
// base, doubled for each failure beyond LockoutAfter, at most the max.
func (c Config) LockFor(failures int) time.Duration {
	d := c.LockoutBase
	for i := c.LockoutAfter; i < failures && d < c.LockoutMax; i++ {
		d *= 2
	}
	return min(d, c.LockoutMax)
}

// countMFAFailure adds one failure to the budget of the account and
// locks it when the budget is spent; a lock is an mfa_locked event.
func (s *Service) countMFAFailure(ctx context.Context, tx Tx, u User, now time.Time) error {
	if s.Config.LockoutAfter <= 0 {
		return nil
	}
	l := MFALock{Failures: u.MFAFailures + 1, LockedUntil: u.MFALockedUntil, HardLocked: u.MFAHardLocked}
	locked := false
	switch {
	case s.Config.HardLockAfter > 0 && l.Failures >= s.Config.HardLockAfter:
		l.HardLocked, locked = true, true
	case l.Failures >= s.Config.LockoutAfter:
		until := now.Add(s.Config.LockFor(l.Failures))
		l.LockedUntil, locked = &until, true
	}
	if err := tx.SetMFALock(ctx, u.ID, l); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	s.count(CounterMFALocked)
	return tx.Record(ctx, audit.Event{
		Actor: audit.SystemActor("mfa-lockout"), EntityType: "user", EntityID: u.ID, EventType: audit.EventMFALocked,
		Payload: map[string]any{"failures": l.Failures, "locked_until": l.LockedUntil, "until_unlocked": l.HardLocked},
	})
}

// UnlockMFA clears the MFA failures and lock of an account (admin).
func (s *Service) UnlockMFA(ctx context.Context, id string, actor audit.Actor) (User, error) {
	return s.change(ctx, id, actor, audit.EventUserMFAUnlocked, "", func(tx Tx, before User) (User, error) {
		if err := tx.SetMFALock(ctx, id, MFALock{}); err != nil {
			return User{}, err
		}
		u := before
		u.MFAFailures, u.MFALockedUntil, u.MFAHardLocked = 0, nil, false
		return u, nil
	})
}

func (s *Service) refuseMFA(ctx context.Context, actor audit.Actor, ri apiserver.RequestInfo, reason string) {
	s.count(CounterMFARefused)
	s.recordOwnTx(ctx, audit.Event{
		Actor: actor, EntityType: "user", EntityID: actor.ID, EventType: audit.EventMFARefused,
		Payload: map[string]any{"reason": reason, "remote_ip": ri.RemoteIP},
	})
}

// startSession bounds the account's live sessions (the oldest beyond the
// limit is revoked), inserts the session row and signs its token.
func (s *Service) startSession(ctx context.Context, tx Tx, u User, ri apiserver.RequestInfo, byRecovery bool, now time.Time) (string, Session, error) {
	live, err := tx.LiveSessions(ctx, u.ID, now)
	if err != nil {
		return "", Session{}, err
	}
	for i := 0; len(live)-i >= s.Config.MaxSessions; i++ {
		old := live[i].JTI
		if _, err := tx.RevokeSession(ctx, old, now, "system", "session_limit"); err != nil {
			return "", Session{}, err
		}
		s.count(CounterSessionLimitEnded)
		if err := tx.Record(ctx, audit.Event{
			Actor: audit.SystemActor("session-limit"), EntityType: "session", EntityID: old, EventType: audit.EventSessionRevoked,
			Payload: map[string]any{"user_id": u.ID, "reason": "session_limit", "limit": s.Config.MaxSessions},
		}); err != nil {
			return "", Session{}, err
		}
	}
	jti, err := tokens.NewID()
	if err != nil {
		return "", Session{}, err
	}
	sess := Session{
		JTI: jti, UserID: u.ID, Realm: u.Realm, Roles: slices.Clone(u.Roles), IssuedAt: now.Truncate(time.Second),
		RemoteIP: ri.RemoteIP, UserAgent: clip(ri.UserAgent),
	}
	sess.ExpiresAt, sess.LastSeenAt = sess.IssuedAt.Add(s.Config.SessionTTL), sess.IssuedAt
	if err := tx.InsertSession(ctx, sess); err != nil {
		return "", Session{}, err
	}
	token, err := s.Keys.SignSession(tokens.SessionClaims{
		Subject: u.ID, Audience: s.Config.OwnHost, Roles: sess.Roles, Realm: sess.Realm, JTI: jti,
		IssuedAt: sess.IssuedAt, ExpiresAt: sess.ExpiresAt,
	})
	if err != nil {
		return "", Session{}, err
	}
	err = tx.Record(ctx, audit.Event{
		Actor: userActor(u), EntityType: "session", EntityID: jti, EventType: audit.EventSessionStarted,
		Payload: map[string]any{"roles": sess.Roles, "realm": sess.Realm, "exp": sess.ExpiresAt, "kid": s.Keys.ActiveKID(),
			"by_recovery_code": byRecovery, "remote_ip": ri.RemoteIP},
	})
	return token, sess, err
}

// ErrSessionRefused is a session token whose session is not live.
var ErrSessionRefused = errors.New("session refused")

// touchEvery bounds the writes of last_seen_at to one a minute per
// session.
const touchEvery = time.Minute

// CheckSession is the stateful half of a session token's verification:
// the session row exists for that account, is not revoked, has not
// expired and has been used within the idle timeout (table A: idle
// 30 min); an idle session is ended so it stays ended. Its roles and
// realm are the row's.
func (s *Service) CheckSession(ctx context.Context, jti, sub string) (Session, error) {
	now := s.now()
	sess, err := s.Store.Session(ctx, jti)
	if errors.Is(err, ErrNotFound) {
		return Session{}, fmt.Errorf("%w: unknown session", ErrSessionRefused)
	}
	if err != nil {
		return Session{}, err
	}
	switch {
	case sess.UserID != sub:
		return Session{}, fmt.Errorf("%w: the session is not this account's", ErrSessionRefused)
	case sess.RevokedAt != nil:
		return Session{}, fmt.Errorf("%w: the session was ended (%s)", ErrSessionRefused, sess.RevokeReason)
	case !now.Before(sess.ExpiresAt):
		return Session{}, fmt.Errorf("%w: the session expired", ErrSessionRefused)
	case now.Sub(sess.LastSeenAt) > s.Config.IdleTimeout:
		s.count(CounterSessionIdleEnded)
		err := s.Store.InTx(ctx, func(tx Tx) error {
			_, err := tx.RevokeSession(ctx, jti, now, "system", "idle")
			return err
		})
		if err != nil {
			logging.Error(ctx, s.logger(), "idle session not ended", err)
		}
		return Session{}, fmt.Errorf("%w: the session was idle longer than %s", ErrSessionRefused, s.Config.IdleTimeout)
	}
	if now.Sub(sess.LastSeenAt) >= touchEvery {
		if err := s.Store.TouchSession(ctx, jti, now); err != nil {
			return Session{}, err
		}
		sess.LastSeenAt = now
	}
	return sess, nil
}

// Logout ends the caller's session.
func (s *Service) Logout(ctx context.Context, id apiserver.Identity) error {
	now := s.now()
	return s.Store.InTx(ctx, func(tx Tx) error {
		if _, err := tx.RevokeSession(ctx, id.JTI, now, id.Subject, "logout"); err != nil {
			return err
		}
		return tx.Record(ctx, audit.Event{
			Actor: audit.Actor{Type: audit.ActorUser, ID: id.Subject, Realm: id.Realm}, EntityType: "session", EntityID: id.JTI,
			EventType: audit.EventLogout,
		})
	})
}

// IdleExpiry is when a session last seen at lastSeen ends for idleness.
func (s *Service) IdleExpiry(lastSeen time.Time) time.Time { return lastSeen.Add(s.Config.IdleTimeout) }

// sweepLock keeps several api replicas from sweeping at once.
const sweepLock = "sessions_sweep"

// SweepRetention keeps an expired session row this long for the record
// before the sweep deletes it (the events rows stay).
const SweepRetention = 24 * time.Hour

// Sweep deletes sessions expired more than SweepRetention ago and
// challenges expired more than an hour ago: the tables stay bounded by
// the sign-in rate times their lifetimes (E-10).
func (s *Service) Sweep(ctx context.Context) (sessions, challenges int64, err error) {
	now := s.now()
	err = s.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, sweepLock); err != nil {
			return err
		}
		if sessions, err = tx.DeleteExpiredSessions(ctx, now.Add(-SweepRetention)); err != nil {
			return err
		}
		challenges, err = tx.DeleteExpiredChallenges(ctx, now.Add(-time.Hour))
		return err
	})
	if err == nil {
		for range sessions {
			s.count(CounterSessionsSwept)
		}
	}
	return sessions, challenges, err
}

// RunSweep sweeps every interval until ctx ends.
func (s *Service) RunSweep(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, _, err := s.Sweep(ctx); err != nil && ctx.Err() == nil {
				logging.Error(ctx, s.logger(), "session sweep failed; it runs again next interval", err)
			}
		}
	}
}
