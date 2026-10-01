package authz

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/tokens"
)

// NewUser is an account to create.
type NewUser struct {
	Username    string
	Password    string
	DisplayName string
	Roles       []string
	Realm       string
}

// MaxDisplayName bounds users.display_name.
const MaxDisplayName = 200

func validateRoles(field string, roles []string) []error {
	var errs []error
	for i, r := range roles {
		f := field + "[" + strconv.Itoa(i) + "]"
		if !slices.Contains(apiserver.AllRoles, r) {
			errs = append(errs, core.Fieldf(f, "%q is not a console role", r))
		} else if slices.Index(roles, r) != i {
			errs = append(errs, core.Fieldf(f, "%q appears twice", r))
		}
	}
	return errs
}

func (s *Service) validatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	switch {
	case n < s.Config.PasswordMinLen:
		return core.Fieldf("password", "shorter than %d characters", s.Config.PasswordMinLen)
	case len(pw) > passhash.MaxSecretBytes:
		return core.Fieldf("password", "longer than %d bytes", passhash.MaxSecretBytes)
	case !utf8.ValidString(pw):
		return core.Fieldf("password", "not valid UTF-8")
	}
	return nil
}

func (s *Service) validateNewUser(in *NewUser) error {
	in.Username = NormalizeUsername(in.Username)
	var errs []error
	if !usernamePattern.MatchString(in.Username) {
		errs = append(errs, core.Fieldf("username", "3 to 64 of a-z, 0-9 and . _ @ -, starting with a letter or digit"))
	}
	if err := s.validatePassword(in.Password); err != nil {
		errs = append(errs, err)
	}
	if utf8.RuneCountInString(in.DisplayName) > MaxDisplayName || !utf8.ValidString(in.DisplayName) {
		errs = append(errs, core.Fieldf("display_name", "longer than %d characters or not UTF-8", MaxDisplayName))
	}
	if in.Realm != apiserver.RealmConsole && in.Realm != apiserver.RealmPolice {
		errs = append(errs, core.Fieldf("realm", "must be console or police"))
	}
	errs = append(errs, validateRoles("roles", in.Roles)...)
	return errors.Join(errs...)
}

// CreateUser creates an account with its password. It enrols TOTP at
// its first sign-in.
func (s *Service) CreateUser(ctx context.Context, in NewUser, actor audit.Actor) (User, error) {
	if err := s.validateNewUser(&in); err != nil {
		return User{}, err
	}
	var out User
	err := s.Store.InTx(ctx, func(tx Tx) error {
		var err error
		out, err = s.insertUser(ctx, tx, in, actor, audit.EventUserCreated)
		return err
	})
	return out, err
}

func (s *Service) insertUser(ctx context.Context, tx Tx, in NewUser, actor audit.Actor, eventType string) (User, error) {
	if _, err := tx.UserByUsername(ctx, in.Username); err == nil {
		return User{}, httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "the username is taken",
			core.Fieldf("username", "%q exists", in.Username))
	} else if !errors.Is(err, ErrNotFound) {
		return User{}, err
	}
	id, err := tokens.NewID()
	if err != nil {
		return User{}, err
	}
	hash, err := s.Hasher.Hash(in.Password)
	if err != nil {
		return User{}, err
	}
	now := s.now()
	roles := slices.Clone(in.Roles)
	if roles == nil {
		roles = []string{}
	}
	u, err := tx.InsertUser(ctx, User{ID: id, Username: in.Username, DisplayName: in.DisplayName, Roles: roles, Realm: in.Realm,
		CreatedAt: now, CreatedBy: actor.ID})
	if err != nil {
		return User{}, err
	}
	if err := tx.SetPassword(ctx, id, hash, now); err != nil {
		return User{}, err
	}
	return u, tx.Record(ctx, audit.Event{
		Actor: actor, EntityType: "user", EntityID: id, EventType: eventType,
		Payload: map[string]any{"username": u.Username, "roles": roles, "realm": u.Realm},
	})
}

func userNotFound(id string) error {
	return httpx.Refuse(http.StatusNotFound, httpx.SlugNotFound, "no such account", core.Fieldf("user_id", "%q does not exist", clip(id)))
}

// lastAdminGuard refuses a change that would leave no active console
// admin: nobody could then manage accounts or keys.
func lastAdminGuard(ctx context.Context, tx Tx, before User, stillAdmin bool) error {
	wasAdmin := before.Status == StatusActive && before.Realm == apiserver.RealmConsole && slices.Contains(before.Roles, apiserver.RoleAdmin)
	if !wasAdmin || stillAdmin {
		return nil
	}
	n, err := tx.CountActiveAdmins(ctx)
	if err != nil {
		return err
	}
	if n <= 1 {
		return httpx.Refuse(http.StatusConflict, httpx.SlugConflict, "this is the last active admin",
			core.Fieldf("user_id", "the change would leave no active admin"))
	}
	return nil
}

// change runs fn on account id inside a transaction, revokes the
// account's sessions when revoke is set, and records eventType with the
// before and after states.
func (s *Service) change(ctx context.Context, id string, actor audit.Actor, eventType, revokeReason string,
	fn func(tx Tx, before User) (User, error)) (User, error) {
	now := s.now()
	var out User
	err := s.Store.InTx(ctx, func(tx Tx) error {
		before, err := tx.UserByID(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return userNotFound(id)
		}
		if err != nil {
			return err
		}
		if out, err = fn(tx, before); err != nil {
			return err
		}
		var revoked []string
		if revokeReason != "" {
			if revoked, err = tx.RevokeUserSessions(ctx, id, now, actor.ID, revokeReason); err != nil {
				return err
			}
		}
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "user", EntityID: id, EventType: eventType,
			Payload: map[string]any{
				"before":           map[string]any{"roles": before.Roles, "status": before.Status},
				"after":            map[string]any{"roles": out.Roles, "status": out.Status},
				"sessions_revoked": revoked,
			},
		})
	})
	return out, err
}

// SetRoles replaces an account's roles and ends its sessions.
func (s *Service) SetRoles(ctx context.Context, id string, roles []string, actor audit.Actor) (User, error) {
	if err := errors.Join(validateRoles("roles", roles)...); err != nil {
		return User{}, err
	}
	return s.change(ctx, id, actor, audit.EventUserRolesChanged, "roles_changed", func(tx Tx, before User) (User, error) {
		if err := lastAdminGuard(ctx, tx, before, slices.Contains(roles, apiserver.RoleAdmin)); err != nil {
			return User{}, err
		}
		return tx.SetUserRoles(ctx, id, roles, s.now(), actor.ID)
	})
}

// SetStatus disables (ending the sessions) or enables an account.
func (s *Service) SetStatus(ctx context.Context, id, status string, actor audit.Actor) (User, error) {
	eventType, reason := audit.EventUserEnabled, ""
	if status == StatusDisabled {
		eventType, reason = audit.EventUserDisabled, "user_disabled"
	}
	return s.change(ctx, id, actor, eventType, reason, func(tx Tx, before User) (User, error) {
		if status == StatusDisabled {
			if err := lastAdminGuard(ctx, tx, before, false); err != nil {
				return User{}, err
			}
		}
		return tx.SetUserStatus(ctx, id, status, s.now(), actor.ID)
	})
}

// ResetMFA deletes an account's TOTP and recovery codes and ends its
// sessions: it enrols again at its next sign-in.
func (s *Service) ResetMFA(ctx context.Context, id string, actor audit.Actor) (User, error) {
	return s.change(ctx, id, actor, audit.EventUserMFAReset, "mfa_reset", func(tx Tx, before User) (User, error) {
		return before, tx.DeleteMFA(ctx, id)
	})
}

// RevokeSessions ends every live session of an account.
func (s *Service) RevokeSessions(ctx context.Context, id string, actor audit.Actor) (int, error) {
	now := s.now()
	var n int
	err := s.Store.InTx(ctx, func(tx Tx) error {
		if _, err := tx.UserByID(ctx, id); errors.Is(err, ErrNotFound) {
			return userNotFound(id)
		} else if err != nil {
			return err
		}
		revoked, err := tx.RevokeUserSessions(ctx, id, now, actor.ID, "revoked_by_admin")
		if err != nil {
			return err
		}
		n = len(revoked)
		return tx.Record(ctx, audit.Event{
			Actor: actor, EntityType: "session", EntityID: id, EventType: audit.EventSessionRevoked,
			Payload: map[string]any{"user_id": id, "reason": "revoked_by_admin", "sessions": revoked},
		})
	})
	return n, err
}

// GetUser reads one account and whether it has confirmed TOTP.
func (s *Service) GetUser(ctx context.Context, id string) (User, bool, error) {
	u, err := s.Store.UserByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return User{}, false, userNotFound(id)
	}
	if err != nil {
		return User{}, false, err
	}
	enrolled, err := s.enrolled(ctx, u.ID)
	return u, enrolled, err
}

func (s *Service) enrolled(ctx context.Context, id string) (bool, error) {
	m, err := s.Store.MFA(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.EnrolledAt != nil, nil
}

// MaxUsersListed bounds a listing (E-10).
const MaxUsersListed = 1000

// ListUsers reads the accounts, with whether each has confirmed TOTP.
func (s *Service) ListUsers(ctx context.Context) ([]User, []bool, error) {
	us, err := s.Store.Users(ctx, MaxUsersListed)
	if err != nil {
		return nil, nil, err
	}
	enrolled := make([]bool, len(us))
	for i := range us {
		if enrolled[i], err = s.enrolled(ctx, us[i].ID); err != nil {
			return nil, nil, err
		}
	}
	return us, enrolled, nil
}

// bootstrapLock serialises the first-admin bootstrap across replicas.
const bootstrapLock = "users_bootstrap"

var bootstrapActor = audit.SystemActor("bootstrap")

// Bootstrap creates the first admin from BOOTSTRAP_ADMIN_USERNAME and
// the password in BOOTSTRAP_ADMIN_PASSWORD_FILE, on an empty users table
// only. When accounts exist it creates nothing, records
// user_bootstrap_refused and says so at error level: the variables are
// one-shot and should be removed. It returns whether it created the
// admin.
func (s *Service) Bootstrap(ctx context.Context, username, passwordFile string) (bool, error) {
	if username == "" {
		return false, nil
	}
	pw, err := readSecretFile(passwordFile)
	if err != nil {
		return false, core.Fieldf("BOOTSTRAP_ADMIN_PASSWORD_FILE", "%v", err)
	}
	in := NewUser{Username: username, Password: pw, Roles: []string{apiserver.RoleAdmin}, Realm: apiserver.RealmConsole}
	if err := s.validateNewUser(&in); err != nil {
		return false, fmt.Errorf("BOOTSTRAP_ADMIN_USERNAME: %w", err)
	}
	created := false
	err = s.Store.InTx(ctx, func(tx Tx) error {
		if err := tx.Lock(ctx, bootstrapLock); err != nil {
			return err
		}
		n, err := tx.CountUsers(ctx)
		if err != nil {
			return err
		}
		if n > 0 {
			return tx.Record(ctx, audit.Event{
				Actor: bootstrapActor, EntityType: "user", EntityID: in.Username, EventType: audit.EventUserBootstrapRefused,
				Payload: map[string]any{"username": in.Username, "reason": "users exist", "users": n},
			})
		}
		if _, err := s.insertUser(ctx, tx, in, bootstrapActor, audit.EventUserBootstrapped); err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return false, fmt.Errorf("bootstrap admin: %w", err)
	}
	if created {
		s.logger().Warn("first admin created from BOOTSTRAP_ADMIN_USERNAME; remove the bootstrap variables and the password file",
			slog.String("username", in.Username))
	} else {
		s.count(CounterBootstrapRefused)
		s.logger().Error("bootstrap refused: accounts exist; remove BOOTSTRAP_ADMIN_USERNAME and BOOTSTRAP_ADMIN_PASSWORD_FILE",
			slog.String("username", in.Username))
	}
	return created, nil
}

func readSecretFile(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // the path is the operator's configuration
	if err != nil {
		return "", fmt.Errorf("%q cannot be read", path)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, passhash.MaxSecretBytes+2))
	if err != nil {
		return "", fmt.Errorf("%q cannot be read", path)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
