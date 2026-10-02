// Package ts is the telemetry database (TimescaleDB) with three query
// sets: the writer (tsdb-writer only, role authority_ts_writer), the
// reader (hot-path processes and api's record reads, role
// authority_ts_reader, SELECT only) and the projector (api's writes of
// the projection tables, role authority_ts_projector, WP-3).
// internal/store's doc.go describes the whole store.
package ts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/projector"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/writer"
)

// The telemetry roles (migration 00002_roles of the timeseries tree).
const (
	ReaderRole = "authority_ts_reader"
	WriterRole = "authority_ts_writer"
	// ProjectorRole writes the projection tables (migration
	// 00003_registry_projection); only api opens it.
	ProjectorRole = "authority_ts_projector"
)

// Reader is a read-only telemetry pool.
type Reader struct {
	pool *pgxpool.Pool
	Q    *reader.Queries
}

// Writer is the hypertable writer's pool; only tsdb-writer opens one.
type Writer struct {
	pool *pgxpool.Pool
	Q    *writer.Queries
}

// Projector is api's pool on the projection tables.
type Projector struct {
	pool *pgxpool.Pool
	Q    *projector.Queries
}

// OpenProjector opens a pool working as ProjectorRole unless o names
// another role, and checks the schema version.
func OpenProjector(ctx context.Context, o store.PoolOptions) (*Projector, error) {
	if o.Role == "" {
		o.Role = ProjectorRole
	}
	pool, err := store.OpenPool(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("telemetry database: %w", err)
	}
	p := &Projector{pool: pool, Q: projector.New(pool)}
	if err := requireSchema(ctx, p.Q.SchemaVersion); err != nil {
		pool.Close()
		return nil, err
	}
	return p, nil
}

// Close closes the pool.
func (p *Projector) Close() { p.pool.Close() }

// Ping checks a connection can be used.
func (p *Projector) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// ProjectorTx is an open projection transaction: the registry writes
// into it before its relational commit and commits it only when the
// relational side is ready to commit too (G-08).
type ProjectorTx struct {
	tx pgx.Tx
	Q  *projector.Queries
}

// Begin opens a projection transaction.
func (p *Projector) Begin(ctx context.Context) (*ProjectorTx, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("projection: begin: %w", err)
	}
	return &ProjectorTx{tx: tx, Q: projector.New(tx)}, nil
}

// Commit commits the projection transaction.
func (t *ProjectorTx) Commit(ctx context.Context) error {
	if err := t.tx.Commit(ctx); err != nil {
		return fmt.Errorf("projection: commit: %w", err)
	}
	return nil
}

// Rollback rolls the projection transaction back; after a commit it
// does nothing.
func (t *ProjectorTx) Rollback(ctx context.Context) {
	_ = t.tx.Rollback(context.WithoutCancel(ctx))
}

// OpenReader opens a pool working as ReaderRole unless o names another
// role, and checks the schema version.
func OpenReader(ctx context.Context, o store.PoolOptions) (*Reader, error) {
	if o.Role == "" {
		o.Role = ReaderRole
	}
	pool, err := store.OpenPool(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("telemetry database: %w", err)
	}
	r := &Reader{pool: pool, Q: reader.New(pool)}
	if err := requireSchema(ctx, r.Q.SchemaVersion); err != nil {
		pool.Close()
		return nil, err
	}
	return r, nil
}

// OpenWriter opens a pool working as WriterRole unless o names another
// role, and checks the schema version.
func OpenWriter(ctx context.Context, o store.PoolOptions) (*Writer, error) {
	if o.Role == "" {
		o.Role = WriterRole
	}
	pool, err := store.OpenPool(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("telemetry database: %w", err)
	}
	w := &Writer{pool: pool, Q: writer.New(pool)}
	if err := requireSchema(ctx, w.Q.SchemaVersion); err != nil {
		pool.Close()
		return nil, err
	}
	return w, nil
}

// Close closes the pool.
func (r *Reader) Close() { r.pool.Close() }

// ReadTx runs fn in one read-only, repeatable-read transaction, so
// several reads see one state of the database (a projection read whole).
func (r *Reader) ReadTx(ctx context.Context, fn func(q *reader.Queries) error) error {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("telemetry read: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	return fn(reader.New(tx))
}

// Ping checks a connection can be used.
func (r *Reader) Ping(ctx context.Context) error { return r.pool.Ping(ctx) }

// Close closes the pool.
func (w *Writer) Close() { w.pool.Close() }

// Ping checks a connection can be used.
func (w *Writer) Ping(ctx context.Context) error { return w.pool.Ping(ctx) }

func requireSchema(ctx context.Context, version func(context.Context) (int64, error)) error {
	want, err := migrate.Latest(migrate.Timeseries)
	if err != nil {
		return err
	}
	got, err := version(ctx)
	if err != nil {
		if store.IsNoRows(err) || store.SQLState(err) == "42P01" {
			return store.RequireVersion(migrate.Timeseries.Name, 0, want)
		}
		return fmt.Errorf("read timeseries schema version: %w", err)
	}
	return store.RequireVersion(migrate.Timeseries.Name, got, want)
}
