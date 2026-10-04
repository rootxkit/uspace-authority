package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Read needs the relational database: on a store whose transactions
// have no queries it refuses before fn runs. The portal's integration
// tests run it on the relational one.
func TestReadRefusesAStoreWithoutQueries(t *testing.T) {
	f := newFixture(t)
	ran := false
	err := f.svc.Read(context.Background(), func(*gen.Queries, Reader) error { ran = true; return nil })
	if !errors.Is(err, errNoQueries) || ran {
		t.Fatalf("read on the in-memory store: %v (fn ran %v)", err, ran)
	}
}

// The transaction's reader answers as the service does: a free number
// and a taken one (compared ignoring case), a number the pattern
// refuses, an operator found by its source and one not.
func TestReaderInATransaction(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	in := naturalOperator(numberA)
	in.Source, in.SourceRef = SourcePortal, "application-1"
	op := f.operator(t, in)
	err := f.store.InTx(ctx, func(tx Tx) error {
		r := txReader{s: f.svc, tx: tx}
		if p, free, err := r.NumberFree(ctx, numberB); err != nil || !free || p != numberB {
			t.Errorf("free: %q %v %v", p, free, err)
		}
		if _, free, err := r.NumberFree(ctx, "GEOtest00000001"); err != nil || free {
			t.Errorf("taken: %v %v", free, err)
		}
		if _, _, err := r.NumberFree(ctx, "GE1"); err == nil {
			t.Error("a number the pattern refuses was free")
		}
		if got, found, err := r.OperatorBySource(ctx, SourcePortal, "application-1"); err != nil || !found || got.ID != op.ID {
			t.Errorf("by source: %+v %v %v", got, found, err)
		}
		if _, found, err := r.OperatorBySource(ctx, SourcePortal, "application-2"); err != nil || found {
			t.Errorf("unknown source ref: %v %v", found, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
