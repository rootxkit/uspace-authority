// Package pg is the relational database (PostgreSQL + PostGIS), opened
// by api only (plan §3). It holds the pool, the sqlc query set
// (queries/ -> gen/), transactions, advisory locks and the schema check;
// internal/store's doc.go describes the whole store.
package pg

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// AppRole is the role api works as (migration 00002_events).
const AppRole = "authority_app"

// DB is the relational pool with the generated queries.
type DB struct {
	pool *pgxpool.Pool
	q    *gen.Queries
}

// Open opens the pool and checks the schema is at least the newest
// migration this build embeds (D7).
func Open(ctx context.Context, o store.PoolOptions) (*DB, error) {
	pool, err := store.OpenPool(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("relational database: %w", err)
	}
	db := &DB{pool: pool, q: gen.New(pool)}
	if err := db.RequireSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the pool.
func (d *DB) Close() { d.pool.Close() }

// Ping checks a connection can be used (the readiness check).
func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

// Queries runs the generated queries outside a transaction.
func (d *DB) Queries() *gen.Queries { return d.q }

// RequireSchema refuses a relational schema older than this build's.
func (d *DB) RequireSchema(ctx context.Context) error { return RequireSchema(ctx, d.q) }

// RequireSchema is the schema check of D7 through q, for a pool of the
// relational database that is not a DB (internal/occurrences' own role).
func RequireSchema(ctx context.Context, q *gen.Queries) error {
	want, err := migrate.Latest(migrate.Relational)
	if err != nil {
		return err
	}
	got, err := q.SchemaVersion(ctx)
	if err != nil {
		if store.IsNoRows(err) || store.SQLState(err) == "42P01" {
			return store.RequireVersion(migrate.Relational.Name, 0, want)
		}
		return fmt.Errorf("read relational schema version: %w", err)
	}
	return store.RequireVersion(migrate.Relational.Name, got, want)
}

// WithTx runs fn in one transaction with the queries bound to it. It
// commits when fn returns nil and rolls back otherwise (or when fn
// panics, through the deferred rollback). A commit that fails after ctx
// ended wraps store.ErrCommitUnknown: whether it committed is unknown.
func (d *DB) WithTx(ctx context.Context, fn func(q *gen.Queries) error) (err error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	err = fn(gen.New(tx))
	if err != nil {
		return err
	}
	err = tx.Commit(ctx)
	if err != nil && ctx.Err() != nil {
		return fmt.Errorf("commit: %w: %w", store.ErrCommitUnknown, err)
	}
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// LockKey derives an advisory lock key from a job or resource name, so
// keys are named in code rather than numbered by hand.
func LockKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64())
}

// Lock is a held session-level advisory lock.
type Lock struct {
	conn *pgxpool.Conn
	key  int64
}

// AdvisoryLock tries to take the session-level advisory lock key on a
// dedicated connection without waiting. acquired is false when another
// session holds it: the caller skips this run of its job. Every periodic
// job takes one, so several api replicas never run a job twice (D1).
func (d *DB) AdvisoryLock(ctx context.Context, key int64) (lock *Lock, acquired bool, err error) {
	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("advisory lock: acquire connection: %w", err)
	}
	if err := conn.QueryRow(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&acquired); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("advisory lock: %w", err)
	}
	if !acquired {
		conn.Release()
		return nil, false, nil
	}
	return &Lock{conn: conn, key: key}, true, nil
}

// Release unlocks and returns the connection to the pool. When the
// unlock fails the connection is destroyed, which ends the session and
// with it the lock.
func (l *Lock) Release(ctx context.Context) error {
	var unlocked bool
	err := l.conn.QueryRow(ctx, "SELECT pg_advisory_unlock($1)", l.key).Scan(&unlocked)
	if err == nil && !unlocked {
		err = errors.New("advisory lock was not held")
	}
	if err != nil {
		_ = l.conn.Conn().Close(context.WithoutCancel(ctx))
		l.conn.Release()
		return fmt.Errorf("advisory unlock: %w", err)
	}
	l.conn.Release()
	return nil
}
