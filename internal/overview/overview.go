// Package overview serves GET /v1/overview/* (api): the console
// overview's figures, counted in SQL on the database clock. Each
// operation counts one domain (the registry, the U-space airspaces, the
// certificates, the audit log of the last 24 hours) and admits the
// roles of that domain's list operation (apiserver.Roles), so a figure
// is shown only to whoever may open the list behind it. A figure is a
// count: no record, no personal data and no events row.
//
// Every count is index-backed or bounded (migration 00027): the
// registry by status through the status indexes, the newest version of
// each U-space airspace through geo_zones_dataset_identifier_idx, the
// handful of certificates, and the events rows of the window through
// events_ts_idx, at most AuditMaxRows of them. A status, state or entity
// the contract does not name is an error, never dropped from a total.
package overview

import (
	"context"
	"fmt"
	"time"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	pgstore "github.com/rootxkit/uspace-authority/internal/store/pg"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// AuditWindow is the audit figure's window, ending at the database
// clock: "the last 24 hours" is the figure's definition (the contract's
// window_s), not a threshold.
const AuditWindow = 24 * time.Hour

// AuditMaxRows bounds the audit count (E-10): at the bound the figure
// says "at least" (more = true) and the scan stops.
const AuditMaxRows = 100_000

// Queries are the generated count queries (internal/store/pg/queries/overview.sql).
type Queries interface {
	DBNow(ctx context.Context) (time.Time, error)
	OverviewRegistryCounts(ctx context.Context) ([]pggen.OverviewRegistryCountsRow, error)
	OverviewUSpaceCounts(ctx context.Context) ([]pggen.OverviewUSpaceCountsRow, error)
	OverviewCertificateCounts(ctx context.Context) ([]pggen.OverviewCertificateCountsRow, error)
	OverviewAuditEventCount(ctx context.Context, arg pggen.OverviewAuditEventCountParams) (int64, error)
}

// Store runs fn on the queries in one transaction, so as_of (now()) is
// the transaction's time and the counts are read under it.
type Store interface {
	Read(ctx context.Context, fn func(q Queries) error) error
}

// PG is the Store of the relational database.
type PG struct{ DB *pgstore.DB }

// Read implements Store.
func (p PG) Read(ctx context.Context, fn func(q Queries) error) error {
	return p.DB.WithTx(ctx, func(q *pggen.Queries) error { return fn(q) })
}

// Handler serves /v1/overview/* (apiserver.OverviewHandler).
type Handler struct{ Store Store }

var _ apiserver.OverviewHandler = Handler{}

// GetOverviewRegistry counts the registry's operators, UAS and pilots by status.
func (h Handler) GetOverviewRegistry(ctx context.Context, _ gen.GetOverviewRegistryRequestObject) (gen.GetOverviewRegistryResponseObject, error) {
	var out gen.OverviewRegistry
	err := h.Store.Read(ctx, func(q Queries) error {
		now, err := q.DBNow(ctx)
		if err != nil {
			return fmt.Errorf("overview registry: %w", err)
		}
		rows, err := q.OverviewRegistryCounts(ctx)
		if err != nil {
			return fmt.Errorf("overview registry: %w", err)
		}
		out.AsOf = now.UTC()
		for _, r := range rows {
			var c *gen.OverviewRegistryCounts
			switch r.Entity {
			case "operators":
				c = &out.Operators
			case "uas":
				c = &out.Uas
			case "pilots":
				c = &out.Pilots
			default:
				return fmt.Errorf("overview registry: unknown entity %q", r.Entity)
			}
			if err := addRegistry(c, r.Status, r.N); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetOverviewRegistry200JSONResponse(out), nil
}

func addRegistry(c *gen.OverviewRegistryCounts, status string, n int64) error {
	switch gen.RegistryStatus(status) {
	case gen.RegistryStatusActive:
		c.Active += n
	case gen.RegistryStatusSuspended:
		c.Suspended += n
	case gen.RegistryStatusRevoked:
		c.Revoked += n
	case gen.RegistryStatusExpired:
		c.Expired += n
	default:
		return fmt.Errorf("overview registry: unknown status %q", status)
	}
	c.Total += n
	return nil
}

// GetOverviewUSpace counts the newest version of every U-space airspace by state.
func (h Handler) GetOverviewUSpace(ctx context.Context, _ gen.GetOverviewUSpaceRequestObject) (gen.GetOverviewUSpaceResponseObject, error) {
	var out gen.OverviewUSpace
	err := h.Store.Read(ctx, func(q Queries) error {
		now, err := q.DBNow(ctx)
		if err != nil {
			return fmt.Errorf("overview uspace: %w", err)
		}
		rows, err := q.OverviewUSpaceCounts(ctx)
		if err != nil {
			return fmt.Errorf("overview uspace: %w", err)
		}
		out.AsOf = now.UTC()
		for _, r := range rows {
			switch gen.ZoneState(r.State) {
			case gen.ZoneStateDraft:
				out.Draft += r.N
			case gen.ZoneStateApproved:
				out.Approved += r.N
			case gen.ZoneStatePublished:
				out.Published += r.N
			case gen.ZoneStateSuperseded:
				out.Superseded += r.N
			default:
				return fmt.Errorf("overview uspace: unknown state %q", r.State)
			}
			out.Total += r.N
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetOverviewUSpace200JSONResponse(out), nil
}

// GetOverviewCertificates counts the certificates by status.
func (h Handler) GetOverviewCertificates(ctx context.Context, _ gen.GetOverviewCertificatesRequestObject) (gen.GetOverviewCertificatesResponseObject, error) {
	var out gen.OverviewCertificates
	err := h.Store.Read(ctx, func(q Queries) error {
		now, err := q.DBNow(ctx)
		if err != nil {
			return fmt.Errorf("overview certificates: %w", err)
		}
		rows, err := q.OverviewCertificateCounts(ctx)
		if err != nil {
			return fmt.Errorf("overview certificates: %w", err)
		}
		out.AsOf = now.UTC()
		for _, r := range rows {
			switch gen.CertificateStatus(r.Status) {
			case gen.CertificateStatusIssued:
				out.Issued += r.N
			case gen.CertificateStatusOperating:
				out.Operating += r.N
			case gen.CertificateStatusCeased:
				out.Ceased += r.N
			case gen.CertificateStatusSuspended:
				out.Suspended += r.N
			case gen.CertificateStatusLimited:
				out.Limited += r.N
			case gen.CertificateStatusRevoked:
				out.Revoked += r.N
			case gen.CertificateStatusLapsed:
				out.Lapsed += r.N
			default:
				return fmt.Errorf("overview certificates: unknown status %q", r.Status)
			}
			out.Total += r.N
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetOverviewCertificates200JSONResponse(out), nil
}

// GetOverviewAudit counts the events rows of the last AuditWindow, up to AuditMaxRows.
func (h Handler) GetOverviewAudit(ctx context.Context, _ gen.GetOverviewAuditRequestObject) (gen.GetOverviewAuditResponseObject, error) {
	out := gen.OverviewAudit{WindowS: int64(AuditWindow / time.Second)}
	err := h.Store.Read(ctx, func(q Queries) error {
		now, err := q.DBNow(ctx)
		if err != nil {
			return fmt.Errorf("overview audit: %w", err)
		}
		n, err := q.OverviewAuditEventCount(ctx, pggen.OverviewAuditEventCountParams{WindowS: AuditWindow.Seconds(), MaxRows: AuditMaxRows})
		if err != nil {
			return fmt.Errorf("overview audit: %w", err)
		}
		out.AsOf, out.Events, out.More = now.UTC(), n, n >= AuditMaxRows
		return nil
	})
	if err != nil {
		return nil, err
	}
	return gen.GetOverviewAudit200JSONResponse(out), nil
}
