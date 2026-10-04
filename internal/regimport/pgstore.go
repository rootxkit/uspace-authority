package regimport

import (
	"context"

	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// PG is the Ledger on the relational database (registry_imports, as the
// application role; append-only).
type PG struct{ DB *pg.DB }

var _ Ledger = PG{}

// Record implements Ledger.
func (p PG) Record(ctx context.Context, e Entry) error {
	var version *int64
	if e.Version > 0 {
		v := e.Version
		version = &v
	}
	_, err := p.DB.Queries().InsertRegistryImport(ctx, gen.InsertRegistryImportParams{
		ID: e.ID, Kind: e.Kind, Origin: e.Origin, ContentSha256: e.SHA256, RulesVersion: e.RulesVersion, Outcome: e.Outcome,
		RowsRead: int32(e.Records), Created: int32(e.Created), Updated: int32(e.Updated), Unchanged: int32(e.Unchanged),
		Problems: int32(e.Problems), RegistryVersion: version, ActorID: e.ActorID,
	})
	return err
}

// Last implements Ledger.
func (p PG) Last(ctx context.Context, kind, origin string) (Entry, bool, error) {
	r, err := p.DB.Queries().LastRegistryImport(ctx, gen.LastRegistryImportParams{Kind: kind, Origin: origin})
	if store.IsNoRows(err) {
		return Entry{}, false, nil
	}
	if err != nil {
		return Entry{}, false, err
	}
	e := Entry{
		ID: r.ID, At: r.At, Kind: r.Kind, Origin: r.Origin, SHA256: r.ContentSha256, RulesVersion: r.RulesVersion, Outcome: r.Outcome,
		Records: int(r.RowsRead), Created: int(r.Created), Updated: int(r.Updated), Unchanged: int(r.Unchanged),
		Problems: int(r.Problems), ActorID: r.ActorID,
	}
	if r.RegistryVersion != nil {
		e.Version = *r.RegistryVersion
	}
	return e, true, nil
}
