// Package ts is the telemetry database (TimescaleDB) with two query
// sets: the writer (tsdb-writer only, role authority_ts_writer) and the
// reader (hot-path processes and api's record reads, role
// authority_ts_reader, SELECT only). internal/store's doc.go describes
// the whole store.
package ts

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/reader"
	"github.com/rootxkit/uspace-authority/internal/store/ts/gen/writer"
)

// The telemetry roles (migration 00002_roles of the timeseries tree).
const (
	ReaderRole = "authority_ts_reader"
	WriterRole = "authority_ts_writer"
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
