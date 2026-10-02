package ts

import "context"

// Exec runs raw SQL as the reader's role and reports the rows affected
// or returned, for tests that prove what the role may not do.
func (r *Reader) Exec(ctx context.Context, sql string) (int64, error) {
	tag, err := r.pool.Exec(ctx, sql)
	return tag.RowsAffected(), err
}

// Exec is Reader.Exec as the writer's role.
func (w *WriterPool) Exec(ctx context.Context, sql string) (int64, error) {
	tag, err := w.pool.Exec(ctx, sql)
	return tag.RowsAffected(), err
}
