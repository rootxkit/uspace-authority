package ts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rootxkit/uspace-authority/internal/store"
)

// ArchiverRole is api's role for the archive of the telemetry
// hypertables (migration 00013_archive, WP-27): SELECT on the three
// archived hypertables and the ledger archive_chunks, and the two
// functions that list and drop chunks. It holds no DELETE.
const ArchiverRole = "authority_ts_archiver"

// The archived hypertables (spec 05 §4: 90 days online, then the
// archive). ussp_flights is never archived (24 h disposal).
const (
	TableRIDObservations = "rid_observations"
	TableTracks          = "tracks"
	TableMannedTracks    = "manned_tracks"
)

// ArchivedTables are the hypertables the archive job exports, in the
// order it works them.
var ArchivedTables = []string{TableRIDObservations, TableTracks, TableMannedTracks}

// timeColumn is each archived table's time column (its chunks' range).
var timeColumn = map[string]string{
	TableRIDObservations: "ingest_ts",
	TableTracks:          "captured_at",
	TableMannedTracks:    "source_captured_at",
}

// ErrNotArchived names a table the archive does not work.
var ErrNotArchived = errors.New("not an archived hypertable")

// Archiver is api's pool on the archive ledger and the archived
// hypertables.
type Archiver struct {
	pool *pgxpool.Pool
	// ExportTimeout bounds one chunk's export statement (the pool's
	// statement timeout is meant for requests, not for a day of rows).
	ExportTimeout time.Duration
}

// OpenArchiver opens a pool working as ArchiverRole unless o names
// another role, and checks the schema version.
func OpenArchiver(ctx context.Context, o store.PoolOptions) (*Archiver, error) {
	if o.Role == "" {
		o.Role = ArchiverRole
	}
	pool, err := store.OpenPool(ctx, o)
	if err != nil {
		return nil, fmt.Errorf("telemetry database: %w", err)
	}
	a := &Archiver{pool: pool}
	if err := requireSchema(ctx, func(ctx context.Context) (int64, error) {
		var v int64
		err := pool.QueryRow(ctx, `SELECT version_id FROM goose_db_version_timeseries ORDER BY id DESC LIMIT 1`).Scan(&v)
		return v, err
	}); err != nil {
		pool.Close()
		return nil, err
	}
	return a, nil
}

// Close closes the pool.
func (a *Archiver) Close() { a.pool.Close() }

// Ping checks a connection can be used.
func (a *Archiver) Ping(ctx context.Context) error { return a.pool.Ping(ctx) }

// Chunk is one chunk of an archived hypertable.
type Chunk struct {
	Table      string
	Name       string
	RangeStart time.Time
	RangeEnd   time.Time
}

func checkTable(table string) error {
	if _, ok := timeColumn[table]; !ok {
		return fmt.Errorf("%q: %w", table, ErrNotArchived)
	}
	return nil
}

// ExpiredChunks lists table's chunks whose range ended onlineDays ago
// or earlier on the database clock, oldest first, at most limit.
func (a *Archiver) ExpiredChunks(ctx context.Context, table string, onlineDays, limit int) ([]Chunk, error) {
	if err := checkTable(table); err != nil {
		return nil, err
	}
	rows, err := a.pool.Query(ctx, `SELECT chunk_name, range_start, range_end
		FROM authority_archive_chunks($1, now() - make_interval(days => $2)) LIMIT $3`, table, onlineDays, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: chunks of %s: %w", table, err)
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Chunk, error) {
		c := Chunk{Table: table}
		err := r.Scan(&c.Name, &c.RangeStart, &c.RangeEnd)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("archive: chunks of %s: %w", table, err)
	}
	return out, nil
}

// Ledger states of archive_chunks.
const (
	ChunkExporting = "exporting"
	ChunkArchived  = "archived"
	ChunkDropped   = "dropped"
)

// ChunkRecord is an archive_chunks row.
type ChunkRecord struct {
	Table, Chunk           string
	RangeStart, RangeEnd   time.Time
	State                  string
	ObjectKey, ManifestKey string
	Rows, Bytes            *int64
	SHA256                 *string
	PIIRedacted            int64
	PayloadsDropped        int64
	Attempts               int32
	LastError              *string
	ArchivedAt, DroppedAt  *time.Time
	ObjectDeletedAt        *time.Time
	ArchiveAudited         bool
	DropAudited            bool
	DeleteAudited          bool
}

const chunkColumns = `hypertable, chunk_name, range_start, range_end, state, object_key, manifest_key, rows, bytes,
	sha256, pii_redacted, payloads_dropped, attempts, last_error, archived_at, dropped_at, object_deleted_at,
	archive_audited, drop_audited, delete_audited`

func scanChunk(r pgx.CollectableRow) (ChunkRecord, error) {
	var c ChunkRecord
	err := r.Scan(&c.Table, &c.Chunk, &c.RangeStart, &c.RangeEnd, &c.State, &c.ObjectKey, &c.ManifestKey, &c.Rows, &c.Bytes,
		&c.SHA256, &c.PIIRedacted, &c.PayloadsDropped, &c.Attempts, &c.LastError, &c.ArchivedAt, &c.DroppedAt,
		&c.ObjectDeletedAt, &c.ArchiveAudited, &c.DropAudited, &c.DeleteAudited)
	return c, err
}

// Record reads the ledger row of a chunk; found is false without one.
func (a *Archiver) Record(ctx context.Context, table, chunk string) (rec ChunkRecord, found bool, err error) {
	rows, err := a.pool.Query(ctx, `SELECT `+chunkColumns+` FROM archive_chunks WHERE hypertable = $1 AND chunk_name = $2`, table, chunk)
	if err != nil {
		return ChunkRecord{}, false, fmt.Errorf("archive: ledger of %s: %w", chunk, err)
	}
	rec, err = pgx.CollectExactlyOneRow(rows, scanChunk)
	if errors.Is(err, pgx.ErrNoRows) {
		return ChunkRecord{}, false, nil
	}
	if err != nil {
		return ChunkRecord{}, false, fmt.Errorf("archive: ledger of %s: %w", chunk, err)
	}
	return rec, true, nil
}

// StartExport records that an export of c to objectKey begins: a new
// row, or the row of an earlier attempt that never reached archived
// (exporting again, the attempt counted). A row already archived or
// dropped is left alone and reported by ok false.
func (a *Archiver) StartExport(ctx context.Context, c Chunk, objectKey, manifestKey string) (ok bool, err error) {
	tag, err := a.pool.Exec(ctx, `INSERT INTO archive_chunks (hypertable, chunk_name, range_start, range_end, state, object_key, manifest_key, attempts)
		VALUES ($1, $2, $3, $4, 'exporting', $5, $6, 1)
		ON CONFLICT (hypertable, chunk_name) DO UPDATE
		SET state = 'exporting', object_key = EXCLUDED.object_key, manifest_key = EXCLUDED.manifest_key,
		    attempts = archive_chunks.attempts + 1, last_error = NULL, started_at = now(),
		    rows = NULL, bytes = NULL, sha256 = NULL, archived_at = NULL, pii_redacted = 0, payloads_dropped = 0
		WHERE archive_chunks.state = 'exporting'`, c.Table, c.Name, c.RangeStart, c.RangeEnd, objectKey, manifestKey)
	if err != nil {
		return false, fmt.Errorf("archive: start %s: %w", c.Name, err)
	}
	return tag.RowsAffected() == 1, nil
}

// Reexport puts an archived (never dropped) chunk back to exporting:
// rows were written into it after its export, so the object no longer
// holds all of it.
func (a *Archiver) Reexport(ctx context.Context, table, chunk, reason string) error {
	_, err := a.pool.Exec(ctx, `UPDATE archive_chunks SET state = 'exporting', last_error = $3, rows = NULL, bytes = NULL,
		sha256 = NULL, archived_at = NULL, archive_audited = false
		WHERE hypertable = $1 AND chunk_name = $2 AND state = 'archived'`, table, chunk, truncate(reason))
	if err != nil {
		return fmt.Errorf("archive: reexport %s: %w", chunk, err)
	}
	return nil
}

// ExportFailed records why an export did not reach archived.
func (a *Archiver) ExportFailed(ctx context.Context, table, chunk, reason string) error {
	_, err := a.pool.Exec(ctx, `UPDATE archive_chunks SET last_error = $3
		WHERE hypertable = $1 AND chunk_name = $2 AND state = 'exporting'`, table, chunk, truncate(reason))
	if err != nil {
		return fmt.Errorf("archive: record failure of %s: %w", chunk, err)
	}
	return nil
}

func truncate(s string) string {
	if len(s) > 2000 {
		return s[:2000]
	}
	return s
}

// Exported is what a verified export wrote.
type Exported struct {
	Rows, Bytes     int64
	SHA256          string
	PIIRedacted     int64
	PayloadsDropped int64
}

// Archived records a verified object for the chunk.
func (a *Archiver) Archived(ctx context.Context, table, chunk string, e Exported) error {
	tag, err := a.pool.Exec(ctx, `UPDATE archive_chunks SET state = 'archived', rows = $3, bytes = $4, sha256 = $5,
		pii_redacted = $6, payloads_dropped = $7, archived_at = now(), last_error = NULL
		WHERE hypertable = $1 AND chunk_name = $2 AND state = 'exporting'`,
		table, chunk, e.Rows, e.Bytes, e.SHA256, e.PIIRedacted, e.PayloadsDropped)
	if err != nil {
		return fmt.Errorf("archive: record %s archived: %w", chunk, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("archive: %s was not exporting when its export finished", chunk)
	}
	return nil
}

// Drop drops an archived chunk through authority_archive_drop_chunk
// (which refuses unless the ledger and the chunk agree on its rows).
func (a *Archiver) Drop(ctx context.Context, table, chunk string, rows int64) (time.Time, error) {
	var at time.Time
	if err := a.pool.QueryRow(ctx, `SELECT authority_archive_drop_chunk($1, $2, $3)`, table, chunk, rows).Scan(&at); err != nil {
		return time.Time{}, fmt.Errorf("archive: drop %s: %w", chunk, err)
	}
	return at, nil
}

// Steps of the ledger whose events row is written in the relational
// database.
const (
	StepArchive = "archive"
	StepDrop    = "drop"
	StepDelete  = "delete"
)

// MarkAudited records that a step's events row is written.
func (a *Archiver) MarkAudited(ctx context.Context, table, chunk, step string) error {
	col := map[string]string{StepArchive: "archive_audited", StepDrop: "drop_audited", StepDelete: "delete_audited"}[step]
	if col == "" {
		return fmt.Errorf("archive: unknown step %q", step)
	}
	if _, err := a.pool.Exec(ctx, `UPDATE archive_chunks SET `+col+` = true WHERE hypertable = $1 AND chunk_name = $2`, table, chunk); err != nil {
		return fmt.Errorf("archive: mark %s audited: %w", chunk, err)
	}
	return nil
}

// Unaudited lists rows with a step whose events row is not written yet
// (a restart between the two databases' commits), at most limit.
func (a *Archiver) Unaudited(ctx context.Context, limit int) ([]ChunkRecord, error) {
	return a.list(ctx, `WHERE (state IN ('archived', 'dropped') AND NOT archive_audited)
		OR (state = 'dropped' AND NOT drop_audited) OR (object_deleted_at IS NOT NULL AND NOT delete_audited)
		ORDER BY range_start, chunk_name LIMIT $1`, limit)
}

// Pending lists the archived chunks not dropped yet (held, or waiting
// for the next run), at most limit.
func (a *Archiver) Pending(ctx context.Context, limit int) ([]ChunkRecord, error) {
	return a.list(ctx, `WHERE state = 'archived' ORDER BY range_start, chunk_name LIMIT $1`, limit)
}

// ExpiredObjects lists dropped chunks whose object is older than years
// (their range ended before now minus years) and not deleted yet.
func (a *Archiver) ExpiredObjects(ctx context.Context, years, limit int) ([]ChunkRecord, error) {
	return a.list(ctx, `WHERE state = 'dropped' AND object_deleted_at IS NULL
		AND range_end < now() - make_interval(years => $2) ORDER BY range_start, chunk_name LIMIT $1`, limit, years)
}

func (a *Archiver) list(ctx context.Context, where string, args ...any) ([]ChunkRecord, error) {
	rows, err := a.pool.Query(ctx, `SELECT `+chunkColumns+` FROM archive_chunks `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("archive: ledger: %w", err)
	}
	out, err := pgx.CollectRows(rows, scanChunk)
	if err != nil {
		return nil, fmt.Errorf("archive: ledger: %w", err)
	}
	return out, nil
}

// MarkObjectDeleted records that the archived object of a dropped chunk
// was deleted after its archive period.
func (a *Archiver) MarkObjectDeleted(ctx context.Context, table, chunk string) error {
	if _, err := a.pool.Exec(ctx, `UPDATE archive_chunks SET object_deleted_at = now()
		WHERE hypertable = $1 AND chunk_name = $2 AND state = 'dropped' AND object_deleted_at IS NULL`, table, chunk); err != nil {
		return fmt.Errorf("archive: mark %s deleted: %w", chunk, err)
	}
	return nil
}

// LedgerCounts are the ledger's rows by state, for the status line.
type LedgerCounts struct {
	Exporting, Archived, Dropped, ObjectsDeleted int64
}

// Counts counts the ledger by state.
func (a *Archiver) Counts(ctx context.Context) (LedgerCounts, error) {
	var c LedgerCounts
	err := a.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'exporting'), count(*) FILTER (WHERE state = 'archived'),
		count(*) FILTER (WHERE state = 'dropped'), count(*) FILTER (WHERE object_deleted_at IS NOT NULL) FROM archive_chunks`).
		Scan(&c.Exporting, &c.Archived, &c.Dropped, &c.ObjectsDeleted)
	if err != nil {
		return LedgerCounts{}, fmt.Errorf("archive: ledger counts: %w", err)
	}
	return c, nil
}

// HoldsRows reports whether c holds a row of one of the tracks or
// serials (the aircraft a hold or an open incident names). For
// rid_observations a track id is matched through the serials the
// tracks of that id carried around the chunk's range.
func (a *Archiver) HoldsRows(ctx context.Context, c Chunk, trackIDs, serials []string) (bool, error) {
	if err := checkTable(c.Table); err != nil {
		return false, err
	}
	if len(trackIDs) == 0 && len(serials) == 0 {
		return false, nil
	}
	var q string
	switch c.Table {
	case TableTracks:
		q = `SELECT EXISTS (SELECT 1 FROM tracks WHERE captured_at >= $1 AND captured_at < $2
			AND (track_id = ANY ($3::text[]) OR serial = ANY ($4::text[])))`
	case TableRIDObservations:
		q = `SELECT EXISTS (SELECT 1 FROM rid_observations WHERE ingest_ts >= $1 AND ingest_ts < $2
			AND (serial = ANY ($4::text[]) OR serial IN (SELECT t.serial FROM tracks t WHERE t.track_id = ANY ($3::text[])
			     AND t.serial IS NOT NULL AND t.captured_at >= $1 - interval '1 day' AND t.captured_at < $2 + interval '1 day')))`
	default: // manned_tracks: a manned aircraft is named by its ICAO 24-bit address
		q = `SELECT EXISTS (SELECT 1 FROM manned_tracks WHERE source_captured_at >= $1 AND source_captured_at < $2
			AND icao24 = ANY ($3::text[]) AND cardinality($4::text[]) >= 0)`
	}
	var held bool
	if err := a.pool.QueryRow(ctx, q, c.RangeStart, c.RangeEnd, trackIDs, serials).Scan(&held); err != nil {
		return false, fmt.Errorf("archive: holds of %s: %w", c.Name, err)
	}
	return held, nil
}

// SerialsOfTracks are the serials the tracks of trackIDs carried in
// [from, to) (an incident names track ids; a raw frame carries the
// serial).
func (a *Archiver) SerialsOfTracks(ctx context.Context, trackIDs []string, from, to time.Time) ([]string, error) {
	if len(trackIDs) == 0 {
		return nil, nil
	}
	rows, err := a.pool.Query(ctx, `SELECT DISTINCT serial FROM tracks WHERE track_id = ANY ($1::text[])
		AND serial IS NOT NULL AND captured_at >= $2 AND captured_at < $3 LIMIT 10000`, trackIDs, from, to)
	if err != nil {
		return nil, fmt.Errorf("archive: serials of tracks: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("archive: serials of tracks: %w", err)
	}
	return out, nil
}

// ExportRow is one row of an export: its JSON document (to_jsonb of
// the row, the form jsonb_populate_record restores) and the columns
// that name its aircraft, read beside it so the archive job needs no
// JSON parse for the common row.
type ExportRow struct {
	Doc []byte
	// MayCarryOperator is true for a rid_observations row whose
	// msg_type is one of the systemTypes Export was given (an ODID
	// System message or a message pack).
	MayCarryOperator bool
	// Serial is the row's serial; empty when it has none.
	Serial string
	// Ident is the track id (tracks), the transmitter address
	// (rid_observations) or the ICAO 24-bit address (manned_tracks).
	Ident string
	// IDType is rid_observations' ODID id type of Serial; -1 otherwise.
	IDType int
}

// exportColumns are the aircraft columns of each table, in ExportRow's
// order: serial, ident, id type.
var exportColumns = map[string]string{
	TableRIDObservations: "COALESCE(t.serial, ''), t.transmitter, COALESCE(t.id_type, -1)",
	TableTracks:          "COALESCE(t.serial, ''), t.track_id, -1",
	TableMannedTracks:    "'', t.icao24, -1",
}

// exportFields is the number of columns of an exported row.
const exportFields = 5

// Export streams every row of c to each (in no particular order), in
// one COPY statement on one connection (no transaction is held open by
// the application), bounded by ExportTimeout. It returns the rows read.
func (a *Archiver) Export(ctx context.Context, c Chunk, systemTypes []int, each func(ExportRow) error) (int64, error) {
	if err := checkTable(c.Table); err != nil {
		return 0, err
	}
	col := timeColumn[c.Table]
	flag := "false"
	if c.Table == TableRIDObservations && len(systemTypes) > 0 {
		flag = "t.msg_type IN ("
		for i, v := range systemTypes {
			if i > 0 {
				flag += ", "
			}
			flag += strconv.Itoa(v)
		}
		flag += ")"
	}
	// COPY takes no parameters: the bounds are rendered as literals from
	// time values, the table and column names come from fixed maps.
	//nolint:misspell // pgx API name (Identifier.Sanitize)
	sql := fmt.Sprintf(`COPY (SELECT COALESCE(%s, false), %s, to_jsonb(t)::text FROM %s t WHERE t.%s >= '%s'::timestamptz AND t.%s < '%s'::timestamptz) TO STDOUT`,
		flag, exportColumns[c.Table], pgx.Identifier{c.Table}.Sanitize(), col, c.RangeStart.UTC().Format(time.RFC3339Nano), col,
		c.RangeEnd.UTC().Format(time.RFC3339Nano))
	conn, err := a.pool.Acquire(ctx)
	if err != nil {
		return 0, fmt.Errorf("archive: export %s: %w", c.Name, err)
	}
	defer conn.Release()
	if a.ExportTimeout > 0 {
		if _, err := conn.Exec(ctx, `SELECT set_config('statement_timeout', $1, false)`,
			strconv.FormatInt(a.ExportTimeout.Milliseconds(), 10)); err != nil {
			return 0, fmt.Errorf("archive: export %s: %w", c.Name, err)
		}
		defer func() { _, _ = conn.Exec(context.WithoutCancel(ctx), `RESET statement_timeout`) }()
	}
	lw := &lineWriter{each: func(line []byte) error {
		fields := bytes.Split(line, []byte{'\t'})
		if len(fields) != exportFields {
			return fmt.Errorf("archive: an exported row has %d columns, not %d", len(fields), exportFields)
		}
		var vals [exportFields][]byte
		for i, f := range fields {
			v, err := UnescapeCopyText(f)
			if err != nil {
				return err
			}
			vals[i] = v
		}
		idType, err := strconv.Atoi(string(vals[3]))
		if err != nil {
			return fmt.Errorf("archive: an exported id type %q is not a number", vals[3])
		}
		return each(ExportRow{MayCarryOperator: string(vals[0]) == "t", Serial: string(vals[1]), Ident: string(vals[2]),
			IDType: idType, Doc: vals[4]})
	}}
	if _, err := conn.Conn().PgConn().CopyTo(ctx, lw, sql); err != nil {
		return lw.rows, fmt.Errorf("archive: export %s: %w", c.Name, err)
	}
	if len(lw.buf) > 0 {
		return lw.rows, errors.New("archive: the export ended inside a row")
	}
	return lw.rows, nil
}

// lineWriter splits COPY's text output into rows.
type lineWriter struct {
	buf  []byte
	rows int64
	each func([]byte) error
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		if err := w.each(w.buf[:i]); err != nil {
			return 0, err
		}
		w.rows++
		w.buf = w.buf[i+1:]
	}
}

// ErrCopyNull is a column COPY wrote as NULL (a backslash and N): the
// export selects none, so one is a fault, never an empty value.
var ErrCopyNull = errors.New("archive: an exported column is NULL")

// UnescapeCopyText decodes one column of COPY's text format, as the
// PostgreSQL manual's "COPY, File Formats, Text Format" defines it: a
// backslash before b, f, n, r, t or v is that control character, before
// one to three octal digits or x and one or two hex digits a byte, and
// before any other character that character; a backslash and N alone
// is NULL. The integration test round-trips a value with each of them
// through the database (LESSONS E-03).
func UnescapeCopyText(b []byte) ([]byte, error) {
	const bs = '\\'
	if len(b) == 2 && b[0] == bs && b[1] == 'N' {
		return nil, ErrCopyNull
	}
	if bytes.IndexByte(b, bs) < 0 {
		return bytes.Clone(b), nil
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != bs {
			out = append(out, c)
			continue
		}
		if i+1 >= len(b) {
			return nil, errors.New("archive: an exported value ends in a lone backslash")
		}
		i++
		switch e := b[i]; {
		case e == 'b':
			out = append(out, '\b')
		case e == 'f':
			out = append(out, '\f')
		case e == 'n':
			out = append(out, '\n')
		case e == 'r':
			out = append(out, '\r')
		case e == 't':
			out = append(out, '\t')
		case e == 'v':
			out = append(out, '\v')
		case e >= '0' && e <= '7':
			v, n := 0, 0
			for n < 3 && i+n < len(b) && b[i+n] >= '0' && b[i+n] <= '7' {
				v = v*8 + int(b[i+n]-'0')
				n++
			}
			out = append(out, byte(v))
			i += n - 1
		case e == 'x' && i+1 < len(b) && isHex(b[i+1]):
			v, n := 0, 0
			for n < 2 && i+1+n < len(b) && isHex(b[i+1+n]) {
				v = v*16 + hexVal(b[i+1+n])
				n++
			}
			out = append(out, byte(v))
			i += n
		default:
			out = append(out, e)
		}
	}
	return out, nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default:
		return int(c-'A') + 10
	}
}
