package registry

import (
	"context"
	"errors"

	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Reader is the registry read inside a caller's relational transaction
// (WP-20: the portal holds an application's row lock while it asks). A
// read that took a second pooled connection while the caller held the
// first could wait for ever once every connection was held that way.
type Reader interface {
	// NumberFree is Service.NumberFree in the transaction.
	NumberFree(ctx context.Context, number string) (public string, free bool, err error)
	// OperatorBySource is Service.OperatorBySource in the transaction.
	OperatorBySource(ctx context.Context, source, ref string) (Operator, bool, error)
}

// errNoQueries refuses a transaction of a store that is not the
// relational database (the in-memory store of the unit tests).
var errNoQueries = errors.New("registry: this store's transactions have no relational queries")

// queried is a Tx bound to relational queries (pgTx).
type queried interface{ Queries() *gen.Queries }

// Queries implements queried.
func (t pgTx) Queries() *gen.Queries { return t.q }

func queriesOf(tx Tx) (*gen.Queries, error) {
	if q, ok := tx.(queried); ok {
		return q.Queries(), nil
	}
	return nil, errNoQueries
}

// Read runs fn in one relational transaction with the queries bound to
// it, for the caller's own statements, and a Reader over the same
// transaction, so the caller never holds one connection while waiting
// for a second.
func (s *Service) Read(ctx context.Context, fn func(q *gen.Queries, r Reader) error) error {
	return s.Store.InTx(ctx, func(tx Tx) error {
		q, err := queriesOf(tx)
		if err != nil {
			return err
		}
		return fn(q, txReader{s: s, tx: tx})
	})
}

// txReader is Reader on one transaction.
type txReader struct {
	s  *Service
	tx Tx
}

// NumberFree implements Reader.
func (r txReader) NumberFree(ctx context.Context, number string) (string, bool, error) {
	v, err := r.s.validator()
	if err != nil {
		return "", false, err
	}
	if err := v.Validate(number); err != nil {
		return "", false, err
	}
	public, key := v.Public(number)
	_, err = r.tx.OperatorByKey(ctx, key)
	switch {
	case errors.Is(err, ErrNotFound):
		return public, true, nil
	case err != nil:
		return "", false, err
	}
	return public, false, nil
}

// OperatorBySource implements Reader.
func (r txReader) OperatorBySource(ctx context.Context, source, ref string) (Operator, bool, error) {
	o, err := r.tx.OperatorBySourceRef(ctx, source, ref)
	switch {
	case errors.Is(err, ErrNotFound):
		return Operator{}, false, nil
	case err != nil:
		return Operator{}, false, err
	}
	return o.Operator, true, nil
}

// Within is the registry inside one registry change that a caller's
// own statements share (WP-20: a portal approval registers the operator
// and decides the application in one transaction).
type Within interface {
	Reader
	// CreateOperator is Service.CreateOperator in the change. A refusal
	// is counted and returned; the change goes on unless the caller
	// returns an error.
	CreateOperator(ctx context.Context, in NewOperator, actor audit.Actor) (Operator, error)
}

// Change runs fn in one registry change, as every registry write runs
// (LockProjection held, the change numbered), with the queries bound to
// its transaction for the caller's own statements and a Within over it
// for the registry's. Everything commits together or not at all; the
// projection rows a registration collected are written after the commit
// (a loosening change, G-08), so no projection row says active for a
// registration whose transaction rolled back. fn's error is returned
// as it is.
func (s *Service) Change(ctx context.Context, fn func(q *gen.Queries, w Within) error) error {
	return s.commitChange(ctx, func(tx Tx, cs *changeSet) error {
		q, err := queriesOf(tx)
		if err != nil {
			return err
		}
		return fn(q, txWithin{txReader: txReader{s: s, tx: tx}, cs: cs})
	})
}

// txWithin is Within on one change.
type txWithin struct {
	txReader
	cs *changeSet
}

// CreateOperator implements Within.
func (w txWithin) CreateOperator(ctx context.Context, in NewOperator, actor audit.Actor) (Operator, error) {
	p, err := w.s.prepareOperator(&in)
	if err != nil {
		return Operator{}, err
	}
	op, err := w.s.insertOperator(ctx, w.tx, w.cs, &in, &p, actor)
	if err != nil {
		return Operator{}, w.s.refused(err)
	}
	return op, nil
}
