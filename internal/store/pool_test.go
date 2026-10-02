package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestConfigSetsTimeoutApplicationNameAndRole(t *testing.T) {
	cfg, err := PoolOptions{
		URL: "postgres://u:p@localhost:5432/db", MaxConns: 7, StatementTimeout: 15 * time.Second,
		ApplicationName: "uspace-authority-api", Role: "authority_app",
	}.Config()
	if err != nil {
		t.Fatal(err)
	}
	rp := cfg.ConnConfig.RuntimeParams
	if cfg.MaxConns != 7 || rp["statement_timeout"] != "15000" || rp["application_name"] != "uspace-authority-api" || cfg.AfterConnect == nil {
		t.Fatalf("max %d params %v after-connect %v", cfg.MaxConns, rp, cfg.AfterConnect != nil)
	}
}

func TestConfigWithoutRoleKeepsTheLoginRole(t *testing.T) {
	cfg, err := PoolOptions{URL: "postgres://u:p@localhost:5432/db"}.Config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AfterConnect != nil {
		t.Fatal("no role given, yet a SET ROLE hook was installed")
	}
	if _, ok := cfg.ConnConfig.RuntimeParams["statement_timeout"]; ok {
		t.Fatal("statement_timeout set without being asked")
	}
}

func TestConfigRefusesARoleThatIsNotAnIdentifier(t *testing.T) {
	for _, role := range []string{"Authority", "app; DROP TABLE events", "1app", strings.Repeat("a", 64)} {
		if _, err := (PoolOptions{URL: "postgres://localhost/db", Role: role}).Config(); err == nil || !strings.HasPrefix(err.Error(), "role:") {
			t.Errorf("role %q: %v", role, err)
		}
	}
}

func TestConfigRefusesABadURLWithoutEchoingIt(t *testing.T) {
	_, err := PoolOptions{URL: "postgres://user:s3cret@[bad"}.Config()
	if err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("got %v", err)
	}
}

func TestRequireVersionRefusesAnOlderSchemaAndAcceptsTheSameOrNewer(t *testing.T) {
	err := RequireVersion("relational", 2, 3)
	if err == nil || !strings.Contains(err.Error(), "version 2, this build needs 3") || !strings.Contains(err.Error(), "uspace-authority migrate") {
		t.Fatalf("older: %v", err)
	}
	if !IsSchemaError(fmt.Errorf("open: %w", err)) || IsSchemaError(errors.New("connection refused")) {
		t.Fatal("IsSchemaError")
	}
	if err := RequireVersion("relational", 3, 3); err != nil {
		t.Fatalf("same: %v", err)
	}
	if err := RequireVersion("relational", 4, 3); err != nil {
		t.Fatalf("newer: %v", err)
	}
}

func TestErrorHelpers(t *testing.T) {
	if !IsNoRows(pgx.ErrNoRows) || IsNoRows(errors.New("x")) {
		t.Fatal("IsNoRows")
	}
	wrapped := errors.Join(errors.New("ctx"), &pgconn.PgError{Code: StateInsufficientPrivilege})
	if SQLState(wrapped) != StateInsufficientPrivilege || SQLState(errors.New("x")) != "" {
		t.Fatal("SQLState")
	}
}
