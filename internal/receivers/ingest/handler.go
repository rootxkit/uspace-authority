package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// Pattern is the route of the observation ingest.
const Pattern = "POST /v1/rid/observations"

// Counter names of the handler beyond the refusal reasons (E-09).
const (
	CounterBatchesAccepted      = "batches_accepted"
	CounterObservationsAccepted = "observations_accepted"
	CounterEmptyBatches         = "batches_empty"
	CounterBatchesRefused       = "batches_refused"
	// CounterRefusedNoKeys counts the batches refused while the key set
	// held no receiver at all (each is also refused_unauthenticated).
	CounterRefusedNoKeys = "refused_no_receiver_keys"
	ReasonInFlight       = "refused_in_flight"
	SlugInFlight         = "in_flight"
)

// Recorder takes each receiver's accepted batches and refusals (Status).
type Recorder interface {
	Accepted(id string, b *Batch, fresh, dups int)
	Refused(id, reason string)
}

// Handler is POST /v1/rid/observations: bearer key, then the receiver's
// registry status and source control, then the body (bounded), then
// uspace-core's HMAC, window and nonce check, then the batch, the dedupe
// window and the durable queue write; 202 only after the write (B-05).
type Handler struct {
	Keyring *receivers.Keyring
	Gate    Gate
	Dedupe  *Dedupe
	Queue   Enqueuer
	// Status takes each receiver's accepted and refused requests; nil
	// keeps the process counters only.
	Status Recorder
	// DisabledRetryAfter is the Retry-After of a disabled receiver (B-10).
	DisabledRetryAfter time.Duration
	// QueueRetryAfter is the Retry-After of a queue refusal.
	QueueRetryAfter time.Duration
	// LabHeadersAllowed admits a batch carrying
	// receivers.LabScenarioHeader (LAB_HEADERS_ALLOWED; false, the
	// default, refuses it with 400 lab_header before anything is read
	// or stored: spec 06 §2 T11).
	LabHeadersAllowed bool
	Counters          *core.Counters
	Limiter           *logging.Limiter
	Now               func() time.Time
}

func (h *Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Mount registers the route.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.Handle(Pattern, h)
}

func (h *Handler) oversize(w http.ResponseWriter, r *http.Request, id string) {
	h.refuse(w, r, receivers.Refusal{Status: http.StatusRequestEntityTooLarge, Slug: httpx.SlugBodyTooLarge,
		Counter: receivers.ReasonOversize, Detail: "a batch is at most 65536 bytes"}, id)
}

func (h *Handler) refuse(w http.ResponseWriter, r *http.Request, f receivers.Refusal, receiverID string, errs ...*core.FieldError) {
	h.Counters.Inc(CounterBatchesRefused)
	h.Counters.Inc(f.Counter)
	if receiverID != "" && h.Status != nil {
		h.Status.Refused(receiverID, f.Counter)
	}
	// One line per reason per interval, with the count suppressed between
	// (E-09): a flood of refusals is one line, not thousands.
	h.Limiter.Limited("rid_ingest_refused:"+f.Counter).Warn("observation batch refused",
		slog.String("reason", f.Counter), slog.Int("status", f.Status), slog.String("receiver_id", receiverID),
		slog.String("client_ip", httpx.RemoteIP(r)), slog.String("detail", f.Detail))
	f.Write(w, r, errs...)
}

// cell3 is the work-queue partition of a receiver: the Level3 cell of its
// pinned position (uspace-core geodesy/cell).
func cell3(e *receivers.Entry) (string, error) {
	c, err := cell.Of(core.LatLon{LatDeg: e.LatDeg, LonDeg: e.LonDeg}, cell.Level3)
	if err != nil {
		return "", err
	}
	return c.String(), nil
}

// ServeHTTP serves one batch.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := h.now()
	// The size is bounded before anything is parsed or hashed: a declared
	// length above it is refused at once, and the read stops one byte past
	// it whatever the declaration says.
	if r.ContentLength > receivers.MaxBatchBytes {
		h.oversize(w, r, "")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, receivers.MaxBatchBytes)
	entry, g, err := h.Keyring.Authenticate(r.Context(), r.Header.Get("Authorization"), now)
	if err != nil {
		if h.Keyring.Len() == 0 {
			h.Counters.Inc(CounterRefusedNoKeys)
		}
		h.refuse(w, r, receivers.AuthRefusal(err), "")
		return
	}
	id := entry.ReceiverID
	// T11: a lab simulator's batch never reaches an ingest that has not
	// been told it serves the lab. After the credential, so a request
	// without one is still told 401 first; before the body is read.
	if !h.LabHeadersAllowed && len(r.Header.Values(receivers.LabScenarioHeader)) > 0 {
		h.refuse(w, r, receivers.Refusal{Status: http.StatusBadRequest, Slug: receivers.SlugLabHeader,
			Counter: receivers.ReasonLabHeader, Detail: "this ingest does not admit lab scenario batches (LAB_HEADERS_ALLOWED is false); nothing was stored"}, id,
			core.Fieldf(receivers.LabScenarioHeader, "not admitted by this ingest"))
		return
	}
	if !entry.Enabled() {
		h.refuse(w, r, receivers.Refusal{Status: http.StatusServiceUnavailable, Slug: receivers.SlugSourceDisabled,
			Counter: receivers.ReasonDisabled, Detail: "this receiver is disabled by the authority; nothing was stored",
			RetryAfter: h.DisabledRetryAfter}, id)
		return
	}
	if d := h.Gate.Query(SourceType, &id); !d.Enabled {
		why := "source control"
		if d.WhyDisabled != nil {
			why = "source control (" + string(*d.WhyDisabled) + ")"
		}
		h.refuse(w, r, receivers.Refusal{Status: http.StatusServiceUnavailable, Slug: receivers.SlugSourceDisabled,
			Counter: receivers.ReasonDisabled, Detail: "direct Remote ID is disabled by " + why + "; nothing was stored",
			RetryAfter: h.DisabledRetryAfter}, id)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			h.oversize(w, r, id)
			return
		}
		h.refuse(w, r, receivers.Refusal{Status: http.StatusBadRequest, Slug: receivers.SlugValidation,
			Counter: receivers.ReasonMalformed, Detail: "the body could not be read"}, id)
		return
	}
	report, err := g.Verify(receivers.Datagram(body, r.Header.Get(receivers.SignatureHeader)), now)
	if err != nil {
		h.refuse(w, r, receivers.VerifyRefusal(err), id)
		return
	}
	batch, err := ParseBatch(report.Raw)
	if err != nil {
		h.refuse(w, r, receivers.Refusal{Status: http.StatusBadRequest, Slug: receivers.SlugValidation,
			Counter: receivers.ReasonMalformed, Detail: "not a valid rid/observation/v1 batch"}, id, fieldErrors(err)...)
		return
	}
	h.accept(w, r, &entry, &batch, now)
}

func (h *Handler) accept(w http.ResponseWriter, r *http.Request, entry *receivers.Entry, batch *Batch, now time.Time) {
	id := entry.ReceiverID
	c3, err := cell3(entry)
	if err != nil {
		h.refuse(w, r, receivers.Refusal{Status: http.StatusServiceUnavailable, Slug: receivers.SlugQueueUnavailable,
			Counter: receivers.ReasonQueueUnavailable, Detail: "the receiver's pinned position has no cell", RetryAfter: h.QueueRetryAfter}, id)
		return
	}
	ingestTS := now.UTC()
	rows := Rows(batch, ingestTS)
	keys := make([]string, 0, len(rows))
	keyRow := make([]int, 0, len(rows))
	keep := make([]bool, len(rows))
	for i := range rows {
		if batch.Observations[i].RxTS == nil {
			// Without a receive time there is no dedupe key (T-12).
			keep[i] = true
			continue
		}
		keys = append(keys, rows[i].FrameID)
		keyRow = append(keyRow, i)
	}
	marks := h.Dedupe.Reserve(id, keys, now)
	var reserved []string
	dups := 0
	inFlight := false
	for j, m := range marks {
		switch m {
		case Fresh:
			reserved = append(reserved, keys[j])
			keep[keyRow[j]] = true
		case Duplicate:
			dups++
		case InFlight:
			inFlight = true
		}
	}
	fresh := make([]ridpipe.Row, 0, len(rows))
	for i := range rows {
		if keep[i] {
			fresh = append(fresh, rows[i])
		}
	}
	if inFlight {
		h.Dedupe.Release(id, reserved)
		h.refuse(w, r, receivers.Refusal{Status: http.StatusServiceUnavailable, Slug: SlugInFlight, Counter: ReasonInFlight,
			Detail: "observations of this batch are being queued by another request; retry", RetryAfter: time.Second}, id)
		return
	}
	h.Counters.Add(CounterDuplicates, uint64(dups))
	ack := gen.RIDObservationAck{BatchId: BatchID(id, batch.Nonce), Accepted: len(fresh), Duplicates: dups}
	if len(fresh) == 0 {
		h.Counters.Inc(CounterEmptyBatches)
		h.accepted(id, batch, 0, dups)
		writeAck(w, ack)
		return
	}
	qb := &ridpipe.Batch{
		ID: ack.BatchId, ReceiverID: id, SentAtMS: batch.SentAtMS, Nonce: batch.Nonce, Backlog: batch.Backlog,
		IngestTS: ingestTS, Cell3: c3, Rows: fresh,
	}
	// The write is shared work: a receiver that hangs up must not abort
	// it half way and leave the reservation unsettled (E-14).
	if err := h.Queue.Enqueue(context.WithoutCancel(r.Context()), qb); err != nil {
		h.Dedupe.Release(id, reserved)
		f := receivers.Refusal{Status: http.StatusServiceUnavailable, Slug: receivers.SlugQueueUnavailable,
			Counter: receivers.ReasonQueueUnavailable, Detail: "the work queue did not confirm the write; nothing was accepted",
			RetryAfter: h.QueueRetryAfter}
		if errors.Is(err, ErrQueueFull) {
			f.Slug, f.Counter, f.Detail = receivers.SlugQueueFull, receivers.ReasonQueueFull, "the work queue is full; nothing was accepted"
		}
		logging.Error(r.Context(), h.Limiter.Limited("rid_ingest_queue_error"), "work queue write failed", err, slog.String("receiver_id", id))
		h.refuse(w, r, f, id)
		return
	}
	h.Dedupe.Commit(id, reserved, now)
	h.Counters.Inc(CounterBatchesAccepted)
	h.Counters.Add(CounterObservationsAccepted, uint64(len(fresh)))
	h.accepted(id, batch, len(fresh), dups)
	writeAck(w, ack)
}

func (h *Handler) accepted(id string, b *Batch, fresh, dups int) {
	if h.Status != nil {
		h.Status.Accepted(id, b, fresh, dups)
	}
}

func writeAck(w http.ResponseWriter, ack gen.RIDObservationAck) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(ack)
}

func fieldErrors(err error) []*core.FieldError {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []*core.FieldError
		for _, e := range j.Unwrap() {
			out = append(out, fieldErrors(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return []*core.FieldError{fe}
	}
	return []*core.FieldError{{Field: "body", Reason: err.Error()}}
}
