package authz

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Account statuses (users.status).
const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// User is a row of users.
type User struct {
	ID          string
	Username    string
	DisplayName string
	Roles       []string
	Realm       string
	// Agency and IPAllow are a police account's (WP-19); empty for a
	// console account.
	Agency    string
	IPAllow   []string
	Status    string
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
	// The MFA failure budget of the account (migration 00006).
	MFAFailures    int
	MFALockedUntil *time.Time
	MFAHardLocked  bool
}

// MFALock is the failure state of the MFA of an account.
type MFALock struct {
	Failures    int
	LockedUntil *time.Time
	HardLocked  bool
}

// MFA is a row of user_mfa.
type MFA struct {
	UserID         string
	KeyID          string
	SecretEnc      []byte
	EnrolledAt     *time.Time
	LastStep       int64
	RecoveryHashes []string
}

// Challenge is a row of login_challenges.
type Challenge struct {
	TokenHash string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	Attempts  int
	UsedAt    *time.Time
	RemoteIP  string
}

// Session is a row of sessions.
type Session struct {
	JTI          string
	UserID       string
	Realm        string
	Roles        []string
	IssuedAt     time.Time
	ExpiresAt    time.Time
	LastSeenAt   time.Time
	RevokedAt    *time.Time
	RevokeReason string
	RemoteIP     string
	UserAgent    string
}

// ErrNotFound is a missing row.
var ErrNotFound = errors.New("not found")

// Store is the accounts' view of the relational database.
type Store interface {
	InTx(ctx context.Context, fn func(Tx) error) error
	UserByID(ctx context.Context, id string) (User, error)
	UserByUsername(ctx context.Context, username string) (User, error)
	Users(ctx context.Context, limit int32) ([]User, error)
	PasswordHash(ctx context.Context, userID string) (string, error)
	MFA(ctx context.Context, userID string) (MFA, error)
	Session(ctx context.Context, jti string) (Session, error)
	TouchSession(ctx context.Context, jti string, at time.Time) error
}

// Tx is the work inside one transaction.
type Tx interface {
	Lock(ctx context.Context, name string) error
	Record(ctx context.Context, ev audit.Event) error
	UserByID(ctx context.Context, id string) (User, error)
	// UserForUpdate reads an account and locks its row to the end of
	// the transaction.
	UserForUpdate(ctx context.Context, id string) (User, error)
	SetMFALock(ctx context.Context, id string, l MFALock) error
	UserByUsername(ctx context.Context, username string) (User, error)
	CountUsers(ctx context.Context) (int64, error)
	CountActiveAdmins(ctx context.Context) (int64, error)
	InsertUser(ctx context.Context, u User) (User, error)
	SetUserRoles(ctx context.Context, id string, roles []string, at time.Time, by string) (User, error)
	SetUserStatus(ctx context.Context, id, status string, at time.Time, by string) (User, error)
	// SetUserPoliceAccess replaces a police account's agency and IP
	// allow-list (ErrNotFound for a console account).
	SetUserPoliceAccess(ctx context.Context, id, agency string, allow []string, at time.Time, by string) (User, error)
	SetPassword(ctx context.Context, userID, hash string, at time.Time) error
	MFA(ctx context.Context, userID string) (MFA, error)
	// MFAForUpdate reads the MFA row and locks it to the end of the
	// transaction, so two challenges cannot spend one code.
	MFAForUpdate(ctx context.Context, userID string) (MFA, error)
	SaveMFA(ctx context.Context, m MFA, at time.Time) error
	DeleteMFA(ctx context.Context, userID string) error
	InsertChallenge(ctx context.Context, c Challenge) error
	ChallengeForUpdate(ctx context.Context, tokenHash string) (Challenge, error)
	CountChallengeAttempt(ctx context.Context, tokenHash string) error
	UseChallenge(ctx context.Context, tokenHash string, at time.Time) error
	InsertSession(ctx context.Context, s Session) error
	LiveSessions(ctx context.Context, userID string, now time.Time) ([]Session, error)
	RevokeSession(ctx context.Context, jti string, at time.Time, by, reason string) (bool, error)
	RevokeUserSessions(ctx context.Context, userID string, at time.Time, by, reason string) ([]string, error)
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error)
	DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error)
}

// PG is Store on the relational database.
type PG struct {
	DB    *pg.DB
	Audit *audit.Writer
}

var _ Store = PG{}

// InTx runs fn in one transaction.
func (p PG) InTx(ctx context.Context, fn func(Tx) error) error {
	return p.DB.WithTx(ctx, func(q *gen.Queries) error { return fn(pgTx{q: q, audit: p.Audit}) })
}

// UserByID reads one account.
func (p PG) UserByID(ctx context.Context, id string) (User, error) {
	return userByID(ctx, p.DB.Queries(), id)
}

// UserByUsername reads one account.
func (p PG) UserByUsername(ctx context.Context, username string) (User, error) {
	return userByUsername(ctx, p.DB.Queries(), username)
}

// Users lists accounts by username.
func (p PG) Users(ctx context.Context, limit int32) ([]User, error) {
	rows, err := p.DB.Queries().ListUsers(ctx, limit)
	if err != nil {
		return nil, err
	}
	out := make([]User, 0, len(rows))
	for i := range rows {
		out = append(out, userFrom(&rows[i]))
	}
	return out, nil
}

// PasswordHash reads an account's password hash.
func (p PG) PasswordHash(ctx context.Context, userID string) (string, error) {
	h, err := p.DB.Queries().PasswordHash(ctx, userID)
	if store.IsNoRows(err) {
		return "", ErrNotFound
	}
	return h, err
}

// MFA reads an account's MFA row.
func (p PG) MFA(ctx context.Context, userID string) (MFA, error) {
	return mfaOf(ctx, p.DB.Queries(), userID)
}

// Session reads one session.
func (p PG) Session(ctx context.Context, jti string) (Session, error) {
	r, err := p.DB.Queries().SessionByJTI(ctx, jti)
	if store.IsNoRows(err) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	return sessionFrom(&r), nil
}

// TouchSession moves last_seen_at forward.
func (p PG) TouchSession(ctx context.Context, jti string, at time.Time) error {
	return p.DB.Queries().TouchSession(ctx, gen.TouchSessionParams{Jti: jti, LastSeenAt: at})
}

type pgTx struct {
	q     *gen.Queries
	audit *audit.Writer
}

// Lock implements Tx.
func (t pgTx) Lock(ctx context.Context, name string) error {
	return t.q.AdvisoryXactLock(ctx, pg.LockKey(name))
}

// Record implements Tx.
func (t pgTx) Record(ctx context.Context, ev audit.Event) error {
	_, err := t.audit.Record(ctx, t.q, ev)
	return err
}

// UserByID implements Tx.
func (t pgTx) UserByID(ctx context.Context, id string) (User, error) { return userByID(ctx, t.q, id) }

// UserForUpdate implements Tx.
func (t pgTx) UserForUpdate(ctx context.Context, id string) (User, error) {
	r, err := t.q.UserForUpdate(ctx, id)
	if store.IsNoRows(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

// SetMFALock implements Tx.
func (t pgTx) SetMFALock(ctx context.Context, id string, l MFALock) error {
	return t.q.SetMFALock(ctx, gen.SetMFALockParams{ID: id, MfaFailures: int32(l.Failures), MfaLockedUntil: l.LockedUntil, MfaHardLocked: l.HardLocked})
}

// UserByUsername implements Tx.
func (t pgTx) UserByUsername(ctx context.Context, username string) (User, error) {
	return userByUsername(ctx, t.q, username)
}

// CountUsers implements Tx.
func (t pgTx) CountUsers(ctx context.Context) (int64, error) { return t.q.CountUsers(ctx) }

// CountActiveAdmins implements Tx.
func (t pgTx) CountActiveAdmins(ctx context.Context) (int64, error) {
	return t.q.CountActiveAdmins(ctx)
}

// InsertUser implements Tx.
func (t pgTx) InsertUser(ctx context.Context, u User) (User, error) {
	r, err := t.q.InsertUser(ctx, gen.InsertUserParams{
		ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Roles: nonNil(u.Roles), Realm: u.Realm,
		Agency: optAgency(u.Agency), IpAllow: nonNil(u.IPAllow), CreatedAt: u.CreatedAt, CreatedBy: u.CreatedBy,
	})
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

// SetUserRoles implements Tx.
func (t pgTx) SetUserRoles(ctx context.Context, id string, roles []string, at time.Time, by string) (User, error) {
	r, err := t.q.SetUserRoles(ctx, gen.SetUserRolesParams{ID: id, Roles: nonNil(roles), UpdatedAt: at, UpdatedBy: by})
	if store.IsNoRows(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

// SetUserPoliceAccess implements Tx.
func (t pgTx) SetUserPoliceAccess(ctx context.Context, id, agency string, allow []string, at time.Time, by string) (User, error) {
	r, err := t.q.SetUserPoliceAccess(ctx, gen.SetUserPoliceAccessParams{ID: id, Agency: &agency, IpAllow: nonNil(allow), UpdatedAt: at, UpdatedBy: by})
	if store.IsNoRows(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

func optAgency(a string) *string {
	if a == "" {
		return nil
	}
	return &a
}

// SetUserStatus implements Tx.
func (t pgTx) SetUserStatus(ctx context.Context, id, status string, at time.Time, by string) (User, error) {
	r, err := t.q.SetUserStatus(ctx, gen.SetUserStatusParams{ID: id, Status: status, UpdatedAt: at, UpdatedBy: by})
	if store.IsNoRows(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

// SetPassword implements Tx.
func (t pgTx) SetPassword(ctx context.Context, userID, hash string, at time.Time) error {
	return t.q.UpsertPassword(ctx, gen.UpsertPasswordParams{UserID: userID, PasswordHash: hash, UpdatedAt: at})
}

// MFA implements Tx.
func (t pgTx) MFA(ctx context.Context, userID string) (MFA, error) { return mfaOf(ctx, t.q, userID) }

// MFAForUpdate implements Tx.
func (t pgTx) MFAForUpdate(ctx context.Context, userID string) (MFA, error) {
	r, err := t.q.UserMFAForUpdate(ctx, userID)
	if store.IsNoRows(err) {
		return MFA{}, ErrNotFound
	}
	if err != nil {
		return MFA{}, err
	}
	return MFA{UserID: r.UserID, KeyID: r.KeyID, SecretEnc: r.SecretEnc, EnrolledAt: r.EnrolledAt, LastStep: r.LastStep,
		RecoveryHashes: slices.Clone(r.RecoveryHashes)}, nil
}

// SaveMFA implements Tx.
func (t pgTx) SaveMFA(ctx context.Context, m MFA, at time.Time) error {
	return t.q.UpsertMFA(ctx, gen.UpsertMFAParams{
		UserID: m.UserID, KeyID: m.KeyID, SecretEnc: m.SecretEnc, EnrolledAt: m.EnrolledAt, LastStep: m.LastStep,
		RecoveryHashes: nonNil(m.RecoveryHashes), UpdatedAt: at,
	})
}

// DeleteMFA implements Tx.
func (t pgTx) DeleteMFA(ctx context.Context, userID string) error { return t.q.DeleteMFA(ctx, userID) }

// InsertChallenge implements Tx.
func (t pgTx) InsertChallenge(ctx context.Context, c Challenge) error {
	return t.q.InsertChallenge(ctx, gen.InsertChallengeParams{
		TokenHash: c.TokenHash, UserID: c.UserID, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, RemoteIp: c.RemoteIP,
	})
}

// ChallengeForUpdate implements Tx.
func (t pgTx) ChallengeForUpdate(ctx context.Context, tokenHash string) (Challenge, error) {
	r, err := t.q.ChallengeForUpdate(ctx, tokenHash)
	if store.IsNoRows(err) {
		return Challenge{}, ErrNotFound
	}
	if err != nil {
		return Challenge{}, err
	}
	return Challenge{TokenHash: r.TokenHash, UserID: r.UserID, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt,
		Attempts: int(r.Attempts), UsedAt: r.UsedAt, RemoteIP: r.RemoteIp}, nil
}

// CountChallengeAttempt implements Tx.
func (t pgTx) CountChallengeAttempt(ctx context.Context, tokenHash string) error {
	return t.q.CountChallengeAttempt(ctx, tokenHash)
}

// UseChallenge implements Tx.
func (t pgTx) UseChallenge(ctx context.Context, tokenHash string, at time.Time) error {
	return t.q.UseChallenge(ctx, gen.UseChallengeParams{TokenHash: tokenHash, UsedAt: &at})
}

// InsertSession implements Tx.
func (t pgTx) InsertSession(ctx context.Context, s Session) error {
	return t.q.InsertSession(ctx, gen.InsertSessionParams{
		Jti: s.JTI, UserID: s.UserID, Realm: s.Realm, Roles: nonNil(s.Roles), IssuedAt: s.IssuedAt, ExpiresAt: s.ExpiresAt,
		RemoteIp: s.RemoteIP, UserAgent: s.UserAgent,
	})
}

// LiveSessions implements Tx.
func (t pgTx) LiveSessions(ctx context.Context, userID string, now time.Time) ([]Session, error) {
	rows, err := t.q.LiveSessionsOfUser(ctx, gen.LiveSessionsOfUserParams{UserID: userID, Now: now})
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(rows))
	for i := range rows {
		out = append(out, sessionFrom(&rows[i]))
	}
	return out, nil
}

// RevokeSession implements Tx.
func (t pgTx) RevokeSession(ctx context.Context, jti string, at time.Time, by, reason string) (bool, error) {
	n, err := t.q.RevokeSession(ctx, gen.RevokeSessionParams{Jti: jti, RevokedAt: &at, RevokedBy: &by, RevokeReason: &reason})
	return n > 0, err
}

// RevokeUserSessions implements Tx.
func (t pgTx) RevokeUserSessions(ctx context.Context, userID string, at time.Time, by, reason string) ([]string, error) {
	return t.q.RevokeUserSessions(ctx, gen.RevokeUserSessionsParams{UserID: userID, RevokedAt: &at, RevokedBy: &by, RevokeReason: &reason})
}

// DeleteExpiredSessions implements Tx.
func (t pgTx) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	return t.q.DeleteExpiredSessions(ctx, before)
}

// DeleteExpiredChallenges implements Tx.
func (t pgTx) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	return t.q.DeleteExpiredChallenges(ctx, before)
}

func userByID(ctx context.Context, q *gen.Queries, id string) (User, error) {
	r, err := q.UserByID(ctx, id)
	if store.IsNoRows(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

func userByUsername(ctx context.Context, q *gen.Queries, username string) (User, error) {
	r, err := q.UserByUsername(ctx, username)
	if store.IsNoRows(err) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	return userFrom(&r), nil
}

func mfaOf(ctx context.Context, q *gen.Queries, userID string) (MFA, error) {
	r, err := q.UserMFA(ctx, userID)
	if store.IsNoRows(err) {
		return MFA{}, ErrNotFound
	}
	if err != nil {
		return MFA{}, err
	}
	return MFA{UserID: r.UserID, KeyID: r.KeyID, SecretEnc: r.SecretEnc, EnrolledAt: r.EnrolledAt, LastStep: r.LastStep,
		RecoveryHashes: slices.Clone(r.RecoveryHashes)}, nil
}

func userFrom(r *gen.User) User {
	agency := ""
	if r.Agency != nil {
		agency = *r.Agency
	}
	return User{ID: r.ID, Username: r.Username, DisplayName: r.DisplayName, Roles: slices.Clone(r.Roles), Realm: r.Realm,
		Agency: agency, IPAllow: slices.Clone(r.IpAllow), Status: r.Status, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy, UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
		MFAFailures: int(r.MfaFailures), MFALockedUntil: r.MfaLockedUntil, MFAHardLocked: r.MfaHardLocked}
}

func sessionFrom(r *gen.Session) Session {
	s := Session{JTI: r.Jti, UserID: r.UserID, Realm: r.Realm, Roles: slices.Clone(r.Roles), IssuedAt: r.IssuedAt,
		ExpiresAt: r.ExpiresAt, LastSeenAt: r.LastSeenAt, RevokedAt: r.RevokedAt, RemoteIP: r.RemoteIp, UserAgent: r.UserAgent}
	if r.RevokeReason != nil {
		s.RevokeReason = *r.RevokeReason
	}
	return s
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
