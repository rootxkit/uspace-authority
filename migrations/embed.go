// Package migrations embeds the two goose trees. They are applied only
// by the migrate subcommand (internal/store/migrate), each to its own
// database with its own version table; the trees are never merged.
package migrations

import "embed"

// Relational is the PostgreSQL + PostGIS tree.
//
//go:embed relational/*.sql
var Relational embed.FS

// Timeseries is the TimescaleDB tree.
//
//go:embed timeseries/*.sql
var Timeseries embed.FS
