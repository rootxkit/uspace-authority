package pg

import "context"

// Exec runs raw SQL on the pool, as the pool's role, for tests that
// prove what that role may not do.
func (d *DB) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := d.pool.Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}
