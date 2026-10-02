package receivers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Receiver endpoint patterns served by api outside the generated server
// (x-receiver in api/openapi.yaml).
const (
	PatternConfig    = "GET /v1/rid/receivers/{receiver_id}/config"
	PatternHeartbeat = "POST /v1/rid/receivers/{receiver_id}/heartbeat"
)

// ReceiverAPI serves a receiver's own config and heartbeat on api,
// authenticated by its bearer key (and, for the heartbeat, the body HMAC)
// through the same Keyring and core verifier as rid-ingest.
type ReceiverAPI struct {
	Service  *Service
	Keyring  *Keyring
	Counters *core.Counters
	Limiter  *logging.Limiter
	Now      func() time.Time
}

func (a *ReceiverAPI) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Mount registers the two receiver endpoints on mux.
func (a *ReceiverAPI) Mount(mux *http.ServeMux) {
	mux.Handle(PatternConfig, http.HandlerFunc(a.config))
	mux.Handle(PatternHeartbeat, http.HandlerFunc(a.heartbeat))
}

func (a *ReceiverAPI) refuse(w http.ResponseWriter, r *http.Request, f Refusal, receiverID string, errs ...*core.FieldError) {
	a.Counters.Inc(f.Counter)
	a.Limiter.Limited("rid_receiver_api:"+f.Counter).Warn("receiver request refused",
		slog.String("reason", f.Counter), slog.String("receiver_id", receiverID), slog.String("route", httpx.Route(r)),
		slog.String("client_ip", httpx.RemoteIP(r)), slog.String("detail", f.Detail))
	f.Write(w, r, errs...)
}

// authenticate loads the receiver named by the path from the registry and
// checks the bearer key: it must name the same receiver.
func (a *ReceiverAPI) authenticate(ctx context.Context, r *http.Request) (Entry, *Generation, *Refusal) {
	pathID := r.PathValue("receiver_id")
	header := r.Header.Get("Authorization")
	id, _, err := ParseBearer(header)
	if err != nil || id != pathID {
		f := AuthRefusal(ErrUnauthenticated)
		return Entry{}, nil, &f
	}
	e, err := a.Service.EntryFor(ctx, id)
	if err != nil {
		a.Keyring.Remove(id)
		if errors.Is(err, ErrNotFound) {
			f := AuthRefusal(ErrUnauthenticated)
			return Entry{}, nil, &f
		}
		f := Refusal{Status: http.StatusServiceUnavailable, Slug: SlugBusy, Counter: ReasonBusy,
			Detail: "the receiver registry cannot be read now", RetryAfter: 5 * time.Second}
		logging.Error(ctx, a.Limiter.Limited("rid_receiver_api:registry"), "receiver registry read failed", err)
		return Entry{}, nil, &f
	}
	if err := a.Keyring.Upsert(e); err != nil {
		f := Refusal{Status: http.StatusServiceUnavailable, Slug: SlugBusy, Counter: ReasonBusy,
			Detail: "the receiver's key entry is invalid", RetryAfter: 5 * time.Second}
		logging.Error(ctx, a.Limiter.Limited("rid_receiver_api:entry"), "receiver key entry refused", err, slog.String("receiver_id", id))
		return Entry{}, nil, &f
	}
	entry, g, err := a.Keyring.Authenticate(ctx, header, a.now())
	if err != nil {
		f := AuthRefusal(err)
		return Entry{}, nil, &f
	}
	return entry, g, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Limits are the bounds every receiver is told.
func Limits() gen.RIDIngestLimits {
	return gen.RIDIngestLimits{
		MaxBatchBytes: MaxBatchBytes, MaxObservations: MaxObservations, MaxPayloadBytes: MaxPayloadBytes,
		MaxSkewS: int(MaxSkew / time.Second), NonceWindowS: int(2 * MaxSkew / time.Second),
	}
}

func (a *ReceiverAPI) config(w http.ResponseWriter, r *http.Request) {
	e, _, f := a.authenticate(r.Context(), r)
	if f != nil {
		a.refuse(w, r, *f, r.PathValue("receiver_id"))
		return
	}
	rec, err := a.Service.Get(r.Context(), e.ReceiverID)
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	a.Counters.Inc("config_served")
	writeJSON(w, http.StatusOK, gen.RIDReceiverConfigView{
		ReceiverId: e.ReceiverID, Status: gen.RIDReceiverStatus(rec.Status),
		Config: configOut(rec.Config.Resolve(a.Service.Defaults)), Limits: Limits(),
		SignatureHeader: gen.RIDReceiverConfigViewSignatureHeaderXReportSignature, ServerTimeMs: a.now().UnixMilli(),
	})
}

// heartbeatBody is the signed heartbeat; unknown members are ignored
// within the major version (02 §1).
type heartbeatBody struct {
	ReceiverID string    `json:"receiver_id"`
	SentAtMS   int64     `json:"sent_at_ms"`
	Nonce      string    `json:"nonce"`
	Position   *Position `json:"position"`
	Firmware   *string   `json:"firmware"`
	QueueDepth *int64    `json:"queue_depth"`
}

// parseHeartbeat reads the signed heartbeat bytes core authenticated and
// validates them; it never panics on any input (FuzzParseHeartbeat).
func parseHeartbeat(raw []byte) (heartbeatBody, error) {
	var hb heartbeatBody
	if len(raw) > MaxHeartbeatBytes {
		return heartbeatBody{}, core.Fieldf("body", "longer than %d bytes", MaxHeartbeatBytes)
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&hb); err != nil {
		return heartbeatBody{}, core.Fieldf("body", "not a heartbeat: %v", err)
	}
	if err := hb.validate(); err != nil {
		return heartbeatBody{}, err
	}
	return hb, nil
}

func (b *heartbeatBody) validate() error {
	var errs []error
	if b.Position != nil {
		if !validPosition(b.Position.LatDeg, b.Position.LonDeg) {
			errs = append(errs, core.Fieldf("position", "not a valid WGS84 position"))
		}
		if a := b.Position.AltHAEM; a != nil && (!core.IsFinite(*a) || *a < -1000 || *a > 10000) {
			errs = append(errs, core.Fieldf("position.alt_hae_m", "must be finite, -1000 to 10000"))
		}
	}
	if b.Firmware != nil && len(*b.Firmware) > 100 {
		errs = append(errs, core.Fieldf("firmware", "at most 100 characters"))
	}
	if b.QueueDepth != nil && *b.QueueDepth < 0 {
		errs = append(errs, core.Fieldf("queue_depth", "must not be negative"))
	}
	return errors.Join(errs...)
}

func (a *ReceiverAPI) heartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("receiver_id")
	oversize := Refusal{Status: http.StatusRequestEntityTooLarge, Slug: httpx.SlugBodyTooLarge, Counter: ReasonOversize,
		Detail: "a heartbeat is at most 4096 bytes"}
	if r.ContentLength > MaxHeartbeatBytes {
		a.refuse(w, r, oversize, id)
		return
	}
	// The body is bounded and read before the key check, so a slow body
	// cannot hold an argon2id slot.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxHeartbeatBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			a.refuse(w, r, oversize, id)
			return
		}
		a.refuse(w, r, Refusal{Status: http.StatusBadRequest, Slug: SlugValidation, Counter: ReasonMalformed, Detail: "the body could not be read"}, id)
		return
	}
	_, g, f := a.authenticate(r.Context(), r)
	if f != nil {
		a.refuse(w, r, *f, id)
		return
	}
	report, err := g.Verify(Datagram(body, r.Header.Get(SignatureHeader)), a.now())
	if err != nil {
		a.refuse(w, r, VerifyRefusal(err), id)
		return
	}
	hb, err := parseHeartbeat(report.Raw)
	if err != nil {
		a.refuse(w, r, Refusal{Status: http.StatusBadRequest, Slug: SlugValidation, Counter: ReasonMalformed, Detail: "invalid heartbeat"}, id,
			fieldErrs(err)...)
		return
	}
	res, err := a.Service.Heartbeat(r.Context(), report.ReceiverID, HeartbeatIn{Position: hb.Position, Firmware: hb.Firmware})
	if err != nil {
		httpx.WriteError(w, r, err)
		return
	}
	tol := res.PositionToleranceM
	writeJSON(w, http.StatusOK, gen.RIDHeartbeatAck{
		ReceiverId: report.ReceiverID, Status: gen.RIDReceiverStatus(res.Receiver.Status), LastSeenAt: res.SeenAt,
		PositionDeviationM: res.DeviationM, PositionToleranceM: &tol, ServerTimeMs: a.now().UnixMilli(),
	})
}

// fieldErrs flattens joined field errors.
func fieldErrs(err error) []*core.FieldError {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []*core.FieldError
		for _, e := range j.Unwrap() {
			out = append(out, fieldErrs(e)...)
		}
		return out
	}
	var fe *core.FieldError
	if errors.As(err, &fe) {
		return []*core.FieldError{fe}
	}
	return []*core.FieldError{{Field: "body", Reason: err.Error()}}
}
