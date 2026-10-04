package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rootxkit/uspace-core/core"
)

// PoolOptions configures OpenPool.
type PoolOptions struct {
	// URL is the connection string (a secret: it may carry a password).
	URL string
	// MaxConns bounds the pool; <= 0 keeps pgxpool's default.
	MaxConns int
	// StatementTimeout is set on every connection; <= 0 leaves the
	// server's default.
	StatementTimeout time.Duration
	// ApplicationName names the process in pg_stat_activity.
	ApplicationName string
	// Role is SET on every new connection; empty keeps the login role.
	Role string
}

var roleName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Config parses o into a pool configuration without connecting.
func (o PoolOptions) Config() (*pgxpool.Config, error) {
	cfg, err := pgxpool.ParseConfig(o.URL)
	if err != nil {
		// The parse error may echo the URL, which may carry a password.
		return nil, &core.FieldError{Field: "url", Reason: "not a valid PostgreSQL connection string"}
	}
	if o.MaxConns > 0 {
		cfg.MaxConns = int32(o.MaxConns)
	}
	if o.StatementTimeout > 0 {
		cfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(o.StatementTimeout.Milliseconds(), 10)
	}
	if o.ApplicationName != "" {
		cfg.ConnConfig.RuntimeParams["application_name"] = o.ApplicationName
	}
	if o.Role != "" {
		if !roleName.MatchString(o.Role) {
			return nil, core.Fieldf("role", "%q is not a lower-case role name", o.Role)
		}
		set := "SET ROLE " + pgx.Identifier{o.Role}.Sanitize() //nolint:misspell // pgx API name
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			if _, err := c.Exec(ctx, set); err != nil {
				return fmt.Errorf("set role %s: %w", o.Role, err)
			}
			return nil
		}
	}
	return cfg, nil
}

// OpenPool opens a pool and pings it once, so a wrong URL, password or
// role is reported at start rather than on the first request.
func OpenPool(ctx context.Context, o PoolOptions) (*pgxpool.Pool, error) {
	cfg, err := o.Config()
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect as %s: %w", roleOrLogin(o.Role), err)
	}
	return pool, nil
}

func roleOrLogin(role string) string {
	if role == "" {
		return "the login role"
	}
	return "role " + role
}

// ErrCommitUnknown marks a COMMIT whose context ended while it ran: the
// server may have committed the transaction or not, and the caller
// cannot tell from the error. A caller reports it as unknown, never as
// a rollback.
var ErrCommitUnknown = errors.New("the commit's outcome is unknown: its context ended while it ran")

// IsNoRows reports whether err is "no rows in result set".
func IsNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// SQLState is the PostgreSQL error code of err, or "".
func SQLState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Constraint is the constraint a PostgreSQL error names, or "".
func Constraint(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.ConstraintName
	}
	return ""
}

// SQLStates the callers test for.
const (
	StateInsufficientPrivilege = "42501"
	StateUniqueViolation       = "23505"
	StateCheckViolation        = "23514"
)

// RequireVersion is the start-up check of D7: a process refuses to run
// on a schema older than the newest migration it was built with, and
// says which version it found and which it wants.
func RequireVersion(tree string, got, want int64) error {
	if got < want {
		return &SchemaError{Tree: tree, Got: got, Want: want}
	}
	return nil
}

// SchemaError is RequireVersion's refusal: no retry mends it, a
// migration does (a process that starts degraded on an unreachable
// database still stops on this).
type SchemaError struct {
	Tree      string
	Got, Want int64
}

func (e *SchemaError) Error() string {
	return fmt.Sprintf("%s schema is at version %d, this build needs %d: run `uspace-authority migrate`", e.Tree, e.Got, e.Want)
}

// IsSchemaError reports whether err is a RequireVersion refusal.
func IsSchemaError(err error) bool {
	var se *SchemaError
	return errors.As(err, &se)
}
