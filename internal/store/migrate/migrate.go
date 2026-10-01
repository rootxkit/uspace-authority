package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/rootxkit/uspace-authority/migrations"
)

// Tree is one of the two migration trees. They are separate databases
// with separate version tables and are never merged (CLAUDE.md rule 10).
type Tree struct {
	Name         string // "relational" or "timeseries"
	VersionTable string
	// LockID is the PostgreSQL advisory lock taken while migrating, so
	// two migrate runs never interleave on one database.
	LockID int64
	fsys   fs.FS
}

// FS is the tree's embedded SQL files.
func (t Tree) FS() fs.FS { return t.fsys }

// The two trees, with the version-table names every sibling system uses
// (decision M36).
var (
	Relational = Tree{Name: "relational", VersionTable: "goose_db_version_relational", LockID: 0x75737061636501, fsys: sub(migrations.Relational, "relational")}
	Timeseries = Tree{Name: "timeseries", VersionTable: "goose_db_version_timeseries", LockID: 0x75737061636502, fsys: sub(migrations.Timeseries, "timeseries")}
)

// Trees lists both trees in the order the migrate subcommand applies them.
func Trees() []Tree { return []Tree{Relational, Timeseries} }

func sub(fsys fs.FS, dir string) fs.FS {
	s, err := fs.Sub(fsys, dir)
	if err != nil {
		// fs.Sub fails only for an invalid path literal, which the tests cover.
		return fsys
	}
	return s
}

// Open opens a database/sql pool on url with the pgx driver.
func Open(url string) (*sql.DB, error) {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	return db, nil
}

// Provider returns the goose provider of tree on db, advisory-locked.
func Provider(db *sql.DB, tree Tree, logger *slog.Logger) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockID(tree.LockID))
	if err != nil {
		return nil, fmt.Errorf("%s: session locker: %w", tree.Name, err)
	}
	opts := []goose.ProviderOption{
		goose.WithTableName(tree.VersionTable),
		goose.WithSessionLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	}
	if logger != nil {
		opts = append(opts, goose.WithSlog(logger.With(slog.String("tree", tree.Name))))
	}
	p, err := goose.NewProvider(goose.DialectPostgres, db, tree.fsys, opts...)
	if err != nil {
		return nil, fmt.Errorf("%s: goose provider: %w", tree.Name, err)
	}
	return p, nil
}

// Up applies every pending migration of tree and returns the version
// the database is at afterwards.
func Up(ctx context.Context, db *sql.DB, tree Tree, logger *slog.Logger) (int64, error) {
	p, err := Provider(db, tree, logger)
	if err != nil {
		return 0, err
	}
	if _, err := p.Up(ctx); err != nil {
		return 0, fmt.Errorf("%s: up: %w", tree.Name, err)
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("%s: read version: %w", tree.Name, err)
	}
	return v, nil
}

// DownTo rolls tree back to version (0 removes every migration). Only
// tests and an operator's runbook call it; no process does.
func DownTo(ctx context.Context, db *sql.DB, tree Tree, version int64) error {
	p, err := Provider(db, tree, nil)
	if err != nil {
		return err
	}
	if _, err := p.DownTo(ctx, version); err != nil {
		return fmt.Errorf("%s: down to %d: %w", tree.Name, version, err)
	}
	return nil
}

// Version returns the version tree's database is at.
func Version(ctx context.Context, db *sql.DB, tree Tree) (int64, error) {
	p, err := Provider(db, tree, nil)
	if err != nil {
		return 0, err
	}
	return p.GetDBVersion(ctx)
}
