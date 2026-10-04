// Package store is the occurrences schema's pool (WP-18): the
// relational database opened as the authority_occurrences role, the
// sqlc query set of queries/ (generated into gen/), and transactions
// that bind those queries and the audit log's to one database
// transaction. Only internal/occurrences imports it (the layout test
// holds every other package to that): the application role of the rest
// of api has no grant on the schema, and no other package reaches it
// through this pool either (376/2014 Art. 15-16).
package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-authority/internal/occurrences/store/gen"
	base "github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Role is the role the pool works as (migration 00020_occurrences).
const Role = "authority_occurrences"

// DB is the occurrences pool.
type DB struct {
	pool *pgxpool.Pool
	q    *gen.Queries
}

// Open opens the pool as o.Role and refuses a relational schema older
// than this build's (D7).
func Open(ctx context.Context, o base.PoolOptions) (*DB, error) {
	pool, err := base.OpenPool(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("occurrences database: %w", err)
	}
	if err := pg.RequireSchema(ctx, pggen.New(pool)); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{pool: pool, q: gen.New(pool)}, nil
}

// Close closes the pool.
func (d *DB) Close() { d.pool.Close() }

// Ping checks a connection can be used (a readiness check).
func (d *DB) Ping(ctx context.Context) error { return d.pool.Ping(ctx) }

// Queries runs the occurrences queries outside a transaction.
func (d *DB) Queries() *gen.Queries { return d.q }

// WithTx runs fn in one transaction with the occurrences queries and the
// relational queries the audit writer records through, both bound to it.
// It commits when fn returns nil and rolls back otherwise.
func (d *DB) WithTx(ctx context.Context, fn func(q *gen.Queries, audit *pggen.Queries) error) (err error) {
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()
	err = fn(gen.New(tx), pggen.New(tx))
	if err != nil {
		return err
	}
	err = tx.Commit(ctx)
	if err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
