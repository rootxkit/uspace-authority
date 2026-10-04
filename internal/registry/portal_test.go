package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/httpx"
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

// Change needs the relational database as Read does.
func TestChangeRefusesAStoreWithoutQueries(t *testing.T) {
	f := newFixture(t)
	ran := false
	err := f.svc.Change(context.Background(), func(*gen.Queries, Within) error { ran = true; return nil })
	if !errors.Is(err, errNoQueries) || ran {
		t.Fatalf("change on the in-memory store: %v (fn ran %v)", err, ran)
	}
}

// A registration in a change commits with it and is projected after
// the commit; a number registered already is a counted 409 that leaves
// the change free to go on; a change whose caller fails keeps nothing
// and projects nothing.
func TestWithinRegistersInTheChange(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var op Operator
	err := f.svc.commitChange(ctx, func(tx Tx, cs *changeSet) error {
		w := txWithin{txReader: txReader{s: f.svc, tx: tx}, cs: cs}
		var err error
		if op, err = w.CreateOperator(ctx, naturalOperator(numberA), registrar); err != nil {
			return err
		}
		_, err = w.CreateOperator(ctx, naturalOperator("GEOtest00000001"), registrar)
		if httpx.ProblemFromError(err).Status != 409 {
			t.Errorf("a number registered already: %v", err)
		}
		if _, err := w.CreateOperator(ctx, NewOperator{}, registrar); err == nil {
			t.Error("an empty registration was accepted")
		}
		return nil
	})
	if err != nil || op.ID == "" {
		t.Fatalf("commit %+v %v", op, err)
	}
	if got := f.svc.Counters.Get(CounterRefused); got != 2 {
		t.Fatalf("%d refusals counted, want 2", got)
	}
	if _, ok := f.proj.operators[op.ID]; !ok || len(f.store.operators) != 1 {
		t.Fatalf("committed operator projected %v, stored %d", ok, len(f.store.operators))
	}
	failed := errors.New("the caller's decision failed")
	err = f.svc.commitChange(ctx, func(tx Tx, cs *changeSet) error {
		w := txWithin{txReader: txReader{s: f.svc, tx: tx}, cs: cs}
		if _, err := w.CreateOperator(ctx, naturalOperator(numberB), registrar); err != nil {
			return err
		}
		return failed
	})
	if !errors.Is(err, failed) || len(f.store.operators) != 1 || len(f.proj.operators) != 1 {
		t.Fatalf("failed change: %v, stored %d, projected %d", err, len(f.store.operators), len(f.proj.operators))
	}
}
