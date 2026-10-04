package retention

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/internal/archive"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/store"
	"github.com/rootxkit/uspace-authority/internal/store/pg/gen"
	"github.com/rootxkit/uspace-authority/internal/store/ts"
)

// ArchiveFormat names the archived object's format in its manifest:
// gzip-compressed newline-delimited JSON, one row per line as to_jsonb
// renders it (bytea as "\x" hex), which jsonb_populate_record restores
// (docs/runbooks/retention.md). Parquet would need a dependency this
// repository does not carry (brief WP-27: the choice is recorded).
const ArchiveFormat = "ndjson+gzip; one to_jsonb row per line; restore with jsonb_populate_record"

// Redaction markers added to an archived rid_observations row whose
// payload was changed (06 §5); jsonb_populate_record ignores them, and a
// restored row shows the change as a payload whose SHA-256 differs from
// payload_sha256 (the hash of the frame as received).
const (
	RedactionPositionRemoved = "operator_position_removed"
	RedactionPayloadRemoved  = "payload_removed_undecodable"
	redactionKey             = "archive_redaction"
)

// MaxManifestAircraft bounds the aircraft a manifest lists (E-10); a
// chunk with more lists none and says so (aircraft_complete false), and
// an expiry check then holds the object when any hold names aircraft.
const MaxManifestAircraft = 50000

// maxManifestBytes bounds a manifest read back.
const maxManifestBytes = 16 << 20

// Manifest is the JSON object stored beside each archived chunk.
type Manifest struct {
	Format           string    `json:"format"`
	Hypertable       string    `json:"hypertable"`
	Chunk            string    `json:"chunk"`
	RangeStart       time.Time `json:"range_start"`
	RangeEnd         time.Time `json:"range_end"`
	Object           string    `json:"object"`
	Rows             int64     `json:"rows"`
	Bytes            int64     `json:"bytes"`
	SHA256           string    `json:"sha256"`
	PIIRedacted      int64     `json:"pii_redacted"`
	PayloadsDropped  int64     `json:"payloads_dropped"`
	PositionsKept    int64     `json:"positions_kept_for_incidents"`
	KeptFor          []string  `json:"positions_kept_for,omitempty"`
	TrackIDs         []string  `json:"track_ids"`
	Serials          []string  `json:"serials"`
	AircraftComplete bool      `json:"aircraft_complete"`
	ExportedAt       time.Time `json:"exported_at"`
	OnlineDays       int       `json:"online_days"`
	ArchiveYears     int       `json:"archive_years"`
	PendingGCAA      bool      `json:"pending_gcaa"`
}

// ObjectKeys are the archive keys of a chunk: by table and day, named
// after the chunk.
func ObjectKeys(c ts.Chunk) (object, manifest string) {
	name := c.Name
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	base := fmt.Sprintf("telemetry/%s/%s/%s_%s", c.Table, c.RangeStart.UTC().Format("2006/01/02"),
		c.RangeStart.UTC().Format("20060102T150405Z"), name)
	return base + ".ndjson.gz", base + ".manifest.json"
}

// chunkOutcome is what one chunk came to in a run.
type chunkOutcome struct {
	name     string
	archived bool
	dropped  bool
	held     string
	failed   string
	exported ts.Exported
}

// ArchiveTelemetry archives and drops the chunks of rid_observations,
// tracks and manned_tracks beyond the online window, at most
// ChunksPerRun per run. A chunk is dropped only after its object is
// written, read back and found to hold its rows and hash, and only when
// no hold or open incident names it; a failure leaves it online and is
// reported with the chunk's name.
func (s *Service) ArchiveTelemetry(ctx context.Context) (map[string]any, error) {
	if s.TS == nil {
		return nil, errors.New("no telemetry archiver pool")
	}
	caught, cerr := s.catchUpAudit(ctx)
	if s.Store == nil {
		s.inc(CounterArchiveUnconfigured)
		s.logger().Error("telemetry beyond the online window is neither archived nor dropped: no archive store (ARCHIVE_URL)",
			slog.Int("online_days", s.Periods.OnlineDays))
		return map[string]any{"archived": 0, "dropped": 0, "audit_caught_up": caught}, archive.ErrNotConfigured
	}
	budget := max(s.ChunksPerRun, 1)
	var outcomes []chunkOutcome
	bounded := 0
	var listErrs []error
	for _, table := range ts.ArchivedTables {
		chunks, err := s.TS.ExpiredChunks(ctx, table, s.Periods.OnlineDays, budget+1)
		if err != nil {
			listErrs = append(listErrs, err)
			continue
		}
		for _, c := range chunks {
			if budget == 0 {
				bounded++
				continue
			}
			budget--
			outcomes = append(outcomes, s.chunk(ctx, c))
		}
	}
	if bounded > 0 {
		s.add(CounterChunksBounded, int64(bounded))
	}
	sum, failed := summarise(outcomes)
	sum["audit_caught_up"], sum["left_for_next_run"] = caught, bounded > 0
	s.logger().Info("telemetry archive run", slog.Int("chunks", len(outcomes)), slog.Any("archived", sum["archived"]),
		slog.Any("dropped", sum["dropped"]), slog.Any("held", sum["held"]), slog.Any("failed", sum["failed"]),
		slog.Any("rows_exported", sum["rows_exported"]), slog.Any("bytes", sum["bytes"]),
		slog.Any("frames_pii_redacted", sum["frames_pii_redacted"]), slog.Bool("left_for_next_run", bounded > 0))
	errs := listErrs
	if cerr != nil {
		errs = append(errs, cerr)
	}
	if failed > 0 {
		errs = append(errs, fmt.Errorf("%d chunks were not archived or not dropped; they stay online", failed))
	}
	return sum, errors.Join(errs...)
}

func summarise(outcomes []chunkOutcome) (map[string]any, int) {
	var archivedN, droppedN, rowsN, bytesN, redacted, payloads int64
	archived, dropped := []string{}, []string{}
	held, failed := map[string]string{}, map[string]string{}
	for _, o := range outcomes {
		if o.archived {
			archivedN++
			archived = append(archived, o.name)
			rowsN += o.exported.Rows
			bytesN += o.exported.Bytes
			redacted += o.exported.PIIRedacted
			payloads += o.exported.PayloadsDropped
		}
		if o.dropped {
			droppedN++
			dropped = append(dropped, o.name)
		}
		if o.held != "" {
			held[o.name] = o.held
		}
		if o.failed != "" {
			failed[o.name] = o.failed
		}
	}
	return map[string]any{
		"archived": archivedN, "archived_chunks": archived, "dropped": droppedN, "dropped_chunks": dropped,
		"held": held, "failed": failed, "rows_exported": rowsN, "bytes": bytesN,
		"frames_pii_redacted": redacted, "frames_payload_dropped": payloads,
	}, len(failed)
}

// chunk archives c when it is not archived yet, then drops it unless it
// is held.
func (s *Service) chunk(ctx context.Context, c ts.Chunk) chunkOutcome {
	o := chunkOutcome{name: c.Table + "/" + c.Name}
	rec, found, err := s.TS.Record(ctx, c.Table, c.Name)
	if err != nil {
		return s.chunkFailed(o, c, err)
	}
	var rows int64
	switch {
	case !found || rec.State == ts.ChunkExporting:
		e, err := s.export(ctx, c)
		if err != nil {
			return s.chunkFailed(o, c, err)
		}
		o.archived, o.exported, rows = true, e, e.Rows
	case rec.State == ts.ChunkArchived && rec.Rows != nil:
		rows = *rec.Rows
	default:
		return s.chunkFailed(o, c, fmt.Errorf("the ledger says %s for a chunk that still exists", rec.State))
	}
	held, dropped, err := s.drop(ctx, c, rows)
	switch {
	case err != nil && !dropped:
		if store.SQLState(err) == "55000" {
			// The chunk no longer holds what was archived (rows written
			// into it since): it is exported again by the next run.
			if rerr := s.TS.Reexport(ctx, c.Table, c.Name, err.Error()); rerr != nil {
				err = errors.Join(err, rerr)
			}
		}
		return s.chunkFailed(o, c, err)
	case err != nil:
		s.logger().Warn("chunk dropped; its events row is written by the next run", slog.String("chunk", o.name),
			slog.String("error", err.Error()))
	}
	if held != "" {
		o.held = held
		s.inc(CounterChunksHeld)
		s.logger().Info("archived chunk kept online: it is held", slog.String("chunk", o.name), slog.String("held_by", held))
	}
	if dropped {
		o.dropped = true
		s.inc(CounterChunksDropped)
	}
	return o
}

func (s *Service) chunkFailed(o chunkOutcome, c ts.Chunk, err error) chunkOutcome {
	o.failed = err.Error()
	s.inc(CounterChunksFailed)
	l := s.logger()
	if s.Limiter != nil {
		l = s.Limiter.Limited("retention_chunk:" + c.Table)
	}
	l.Error("telemetry chunk not archived or not dropped; it stays online", slog.String("chunk", o.name),
		slog.Time("range_start", c.RangeStart), slog.Time("range_end", c.RangeEnd), slog.String("error", err.Error()))
	return o
}

// export writes c to the archive store, reads the object back, checks
// its hash, size and row count, stores the manifest and records the
// chunk archived with its events row.
func (s *Service) export(ctx context.Context, c ts.Chunk) (ts.Exported, error) {
	objectKey, manifestKey := ObjectKeys(c)
	ok, err := s.TS.StartExport(ctx, c, objectKey, manifestKey)
	if err != nil {
		return ts.Exported{}, err
	}
	if !ok {
		return ts.Exported{}, errors.New("the ledger moved past exporting under this run")
	}
	// What an interrupted attempt left was never recorded archived.
	for _, k := range []string{objectKey, manifestKey} {
		if err := s.Store.Delete(k); err != nil && !errors.Is(err, archive.ErrNotFound) {
			return ts.Exported{}, s.exportFailed(ctx, c, fmt.Errorf("remove the leftover of an earlier attempt: %w", err))
		}
	}
	exempt, err := s.exemptOver(ctx, s.DB.Queries(), c.RangeStart, c.RangeEnd)
	if err != nil {
		return ts.Exported{}, s.exportFailed(ctx, c, err)
	}
	if len(exempt.TrackIDs) > 0 && exempt.All == "" {
		serials, err := s.TS.SerialsOfTracks(ctx, exempt.TrackIDs, c.RangeStart.Add(-s.IncidentMargin), c.RangeEnd.Add(s.IncidentMargin))
		if err != nil {
			return ts.Exported{}, s.exportFailed(ctx, c, err)
		}
		exempt.addSerials("incident tracks", serials...)
	}
	w, err := s.Store.Create(objectKey)
	if err != nil {
		return ts.Exported{}, s.exportFailed(ctx, c, err)
	}
	hasher := sha256.New()
	var size countWriter
	gz := gzip.NewWriter(io.MultiWriter(w, hasher, &size))
	ac := newAircraft()
	var e ts.Exported
	var kept int64
	n, err := s.TS.Export(ctx, c, archive.SystemTypes, func(r ts.ExportRow) error {
		tracks, serials := aircraftOf(c.Table, &r)
		ac.add(tracks, serials)
		doc := r.Doc
		if r.MayCarryOperator {
			if exempt.All != "" || exempt.matches(tracks, serials) {
				kept++
			} else {
				out, red, err := redactDoc(doc)
				if err != nil {
					return err
				}
				switch red {
				case archive.Redacted:
					e.PIIRedacted++
				case archive.Undecodable:
					e.PayloadsDropped++
				case archive.Unchanged:
				}
				doc = out
			}
		}
		if _, err := gz.Write(doc); err != nil {
			return err
		}
		_, err := gz.Write([]byte{'\n'})
		return err
	})
	if err == nil {
		err = gz.Close()
	}
	if err != nil {
		w.Abort()
		return ts.Exported{}, s.exportFailed(ctx, c, err)
	}
	if err := w.Commit(); err != nil {
		return ts.Exported{}, s.exportFailed(ctx, c, err)
	}
	e.Rows, e.Bytes, e.SHA256 = n, size.n, "sha256:"+hex.EncodeToString(hasher.Sum(nil))
	if err := s.verifyObject(objectKey, e); err != nil {
		return ts.Exported{}, s.exportFailed(ctx, c, fmt.Errorf("the object read back does not verify: %w", err))
	}
	m := Manifest{Format: ArchiveFormat, Hypertable: c.Table, Chunk: c.Name, RangeStart: c.RangeStart.UTC(), RangeEnd: c.RangeEnd.UTC(),
		Object: objectKey, Rows: e.Rows, Bytes: e.Bytes, SHA256: e.SHA256, PIIRedacted: e.PIIRedacted,
		PayloadsDropped: e.PayloadsDropped, PositionsKept: kept, KeptFor: exempt.Why, TrackIDs: ac.trackList(),
		Serials: ac.serialList(), AircraftComplete: !ac.overflow, ExportedAt: time.Now().UTC(),
		OnlineDays: s.Periods.OnlineDays, ArchiveYears: s.Periods.ArchiveYears, PendingGCAA: PendingGCAA}
	if exempt.All != "" {
		m.KeptFor = append(m.KeptFor, exempt.All)
	}
	mb, err := json.Marshal(m)
	if err != nil {
		return ts.Exported{}, s.exportFailed(ctx, c, err)
	}
	if err := archive.Put(s.Store, manifestKey, mb); err != nil {
		return ts.Exported{}, s.exportFailed(ctx, c, err)
	}
	if err := s.TS.Archived(ctx, c.Table, c.Name, e); err != nil {
		return ts.Exported{}, err
	}
	s.inc(CounterChunksArchived)
	s.add(CounterRowsRedacted, e.PIIRedacted)
	s.add(CounterPayloadsDropped, e.PayloadsDropped)
	payload := map[string]any{"hypertable": c.Table, "chunk": c.Name, "range_start": c.RangeStart.UTC().Format(time.RFC3339),
		"range_end": c.RangeEnd.UTC().Format(time.RFC3339), "object": objectKey, "rows": e.Rows, "bytes": e.Bytes,
		"sha256": e.SHA256, "pii_redacted": e.PIIRedacted, "payloads_dropped": e.PayloadsDropped, "positions_kept": kept}
	if err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
		return s.recordOnce(ctx, q, c.Table+"/"+c.Name, audit.EventArchiveChunkArchived, payload)
	}); err != nil {
		s.logger().Warn("chunk archived; its events row is written by the next run", slog.String("chunk", c.Name),
			slog.String("error", err.Error()))
		return e, nil
	}
	if err := s.TS.MarkAudited(ctx, c.Table, c.Name, ts.StepArchive); err != nil {
		s.logger().Warn("chunk archived and audited; the ledger's mark is repeated by the next run", slog.String("error", err.Error()))
	}
	return e, nil
}

func (s *Service) exportFailed(ctx context.Context, c ts.Chunk, err error) error {
	if rerr := s.TS.ExportFailed(context.WithoutCancel(ctx), c.Table, c.Name, err.Error()); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

// verifyObject reads the stored object back: its size and hash must be
// what was written, and it must decompress to exactly e.Rows lines.
func (s *Service) verifyObject(key string, e ts.Exported) error {
	r, err := s.Store.Open(key)
	if err != nil {
		return err
	}
	defer func() { _ = r.Close() }()
	hasher := sha256.New()
	var size countWriter
	tee := io.TeeReader(r, io.MultiWriter(hasher, &size))
	zr, err := gzip.NewReader(tee)
	if err != nil {
		return err
	}
	var lines int64
	br := bufio.NewReaderSize(zr, 1<<16)
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 && chunk[len(chunk)-1] == '\n' {
			lines++
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
	}
	if err := zr.Close(); err != nil {
		return err
	}
	// Drain what gzip did not need (nothing, for a well-formed object).
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return err
	}
	got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	switch {
	case lines != e.Rows:
		return fmt.Errorf("%d rows read back, %d written", lines, e.Rows)
	case size.n != e.Bytes:
		return fmt.Errorf("%d bytes read back, %d written", size.n, e.Bytes)
	case got != e.SHA256:
		return fmt.Errorf("hash %s read back, %s written", got, e.SHA256)
	}
	return nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// aircraftOf names the aircraft of an exported row as the holds and the
// incidents name them: track ids (core's rid ids for a raw frame) and
// serials.
func aircraftOf(table string, r *ts.ExportRow) (tracks, serials []string) {
	if r.Serial != "" {
		serials = []string{r.Serial}
	}
	switch table {
	case ts.TableRIDObservations:
		tracks = []string{rid.UnidentifiedID(r.Ident)}
		if r.Serial != "" && r.IDType >= 0 {
			tracks = append(tracks, rid.AircraftID(odid.IDType(r.IDType), r.Serial))
		}
	default:
		if r.Ident != "" {
			tracks = []string{r.Ident}
		}
	}
	return tracks, serials
}

// aircraft collects the distinct aircraft of a chunk, bounded.
type aircraft struct {
	tracks, serials map[string]struct{}
	overflow        bool
}

func newAircraft() *aircraft {
	return &aircraft{tracks: map[string]struct{}{}, serials: map[string]struct{}{}}
}

func (a *aircraft) add(tracks, serials []string) {
	if a.overflow {
		return
	}
	for _, t := range tracks {
		a.tracks[t] = struct{}{}
	}
	for _, s := range serials {
		a.serials[s] = struct{}{}
	}
	if len(a.tracks)+len(a.serials) > MaxManifestAircraft {
		a.overflow = true
		a.tracks, a.serials = map[string]struct{}{}, map[string]struct{}{}
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (a *aircraft) trackList() []string  { return sortedKeys(a.tracks) }
func (a *aircraft) serialList() []string { return sortedKeys(a.serials) }

// redactDoc removes the remote pilot position from the payload of an
// exported rid_observations row (archive.RedactOperator); an
// undecodable payload is replaced by an empty one. Either change is
// marked in the row.
func redactDoc(doc []byte) ([]byte, archive.Redaction, error) {
	var m map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, 0, fmt.Errorf("archive: an exported row is not a JSON object: %w", err)
	}
	var hexPayload string
	if err := json.Unmarshal(m["payload"], &hexPayload); err != nil {
		return nil, 0, fmt.Errorf("archive: an exported frame has no payload: %w", err)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(hexPayload, `\x`))
	if err != nil {
		return nil, 0, fmt.Errorf("archive: an exported payload is not bytea hex: %w", err)
	}
	out, red := archive.RedactOperator(raw)
	var marker string
	switch red {
	case archive.Unchanged:
		return doc, red, nil
	case archive.Redacted:
		marker = RedactionPositionRemoved
	case archive.Undecodable:
		out, marker = nil, RedactionPayloadRemoved
	}
	p, _ := json.Marshal(`\x` + hex.EncodeToString(out))
	mk, _ := json.Marshal(marker)
	m["payload"], m[redactionKey] = p, mk
	b, err := json.Marshal(m)
	if err != nil {
		return nil, 0, err
	}
	return b, red, nil
}

// catchUpAudit writes the events rows of ledger steps committed in the
// telemetry database whose relational row is missing (a restart or a
// failure between the two commits), at most 1000 per run.
func (s *Service) catchUpAudit(ctx context.Context) (int, error) {
	recs, err := s.TS.Unaudited(ctx, 1000)
	if err != nil {
		return 0, err
	}
	n := 0
	for i := range recs {
		r := &recs[i]
		id := r.Table + "/" + r.Chunk
		steps := []struct {
			step, event string
			need        bool
		}{
			{ts.StepArchive, audit.EventArchiveChunkArchived, !r.ArchiveAudited && r.State != ts.ChunkExporting},
			{ts.StepDrop, audit.EventArchiveChunkDropped, !r.DropAudited && r.State == ts.ChunkDropped},
			{ts.StepDelete, audit.EventArchiveObjectDeleted, !r.DeleteAudited && r.ObjectDeletedAt != nil},
		}
		for _, st := range steps {
			if !st.need {
				continue
			}
			payload := map[string]any{"hypertable": r.Table, "chunk": r.Chunk, "object": r.ObjectKey,
				"range_start": r.RangeStart.UTC().Format(time.RFC3339), "range_end": r.RangeEnd.UTC().Format(time.RFC3339),
				"rows": r.Rows, "sha256": r.SHA256, "recorded_after_restart": true}
			if err := s.DB.WithTx(ctx, func(q *gen.Queries) error {
				return s.recordOnce(ctx, q, id, st.event, payload)
			}); err != nil {
				return n, err
			}
			if err := s.TS.MarkAudited(ctx, r.Table, r.Chunk, st.step); err != nil {
				return n, err
			}
			n++
		}
	}
	if n > 0 {
		s.add(CounterAuditCaughtUp, int64(n))
		s.logger().Warn("archive steps recorded in the audit log after a restart", slog.Int("rows", n))
	}
	return n, nil
}

// drop drops c inside the hold gate unless something holds it; held
// names what holds it. dropped is true once the telemetry database
// dropped it, even when its events row could not be written then (the
// next run writes it).
func (s *Service) drop(ctx context.Context, c ts.Chunk, rows int64) (held string, dropped bool, err error) {
	err = s.DB.WithTx(ctx, func(q *gen.Queries) error {
		if err := q.HoldsGate(ctx); err != nil {
			return err
		}
		h, err := s.holdsOver(ctx, q, c.RangeStart, c.RangeEnd)
		if err != nil {
			return err
		}
		if h.All != "" {
			held = h.All
			return nil
		}
		// As ExpireArchive: an open incident keeps its time whether or
		// not an aircraft has been named for it yet.
		open, err := q.OpenIncidentsAround(ctx, gen.OpenIncidentsAroundParams{FromTs: c.RangeStart.Add(-s.IncidentMargin), ToTs: c.RangeEnd.Add(s.IncidentMargin)})
		if err != nil {
			return err
		}
		if open {
			held = "an open incident occurred within the margin of the chunk's range"
			return nil
		}
		if len(h.TrackIDs)+len(h.Serials) > 0 {
			has, err := s.TS.HoldsRows(ctx, c, h.TrackIDs, h.Serials)
			if err != nil {
				return err
			}
			if has {
				held = "rows of an aircraft named by " + strings.Join(h.Why, ", ")
				return nil
			}
		}
		at, err := s.TS.Drop(ctx, c.Table, c.Name, rows)
		if err != nil {
			return err
		}
		dropped = true
		return s.recordOnce(ctx, q, c.Table+"/"+c.Name, audit.EventArchiveChunkDropped, map[string]any{
			"hypertable": c.Table, "chunk": c.Name, "rows": rows, "dropped_at": at.UTC().Format(time.RFC3339Nano),
			"range_start": c.RangeStart.UTC().Format(time.RFC3339), "range_end": c.RangeEnd.UTC().Format(time.RFC3339),
			"online_days": s.Periods.OnlineDays,
		})
	})
	if err == nil && dropped {
		if merr := s.TS.MarkAudited(ctx, c.Table, c.Name, ts.StepDrop); merr != nil {
			s.logger().Warn("chunk dropped and audited; the ledger's mark is repeated by the next run", slog.String("error", merr.Error()))
		}
	}
	return held, dropped, err
}
