package audit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

// Handler serves GET /v1/audit/events (apiserver.AuditHandler).
type Handler struct {
	Writer *Writer
}

var _ apiserver.AuditHandler = Handler{}

// ActorOf maps the request identity onto an audit actor.
func ActorOf(ctx context.Context) (Actor, error) {
	id, ok := apiserver.IdentityFrom(ctx)
	if !ok || id.Subject == "" {
		return Actor{}, httpx.Refuse(http.StatusUnauthorized, httpx.SlugUnauthn, "no identity on the request")
	}
	t := ActorType(id.ActorType)
	if t == "" {
		t = ActorUser
	}
	return Actor{Type: t, ID: id.Subject, Realm: id.Realm}, nil
}

// ListAuditEvents reads one page and records the read in the same
// transaction: a view of the log is an event too.
func (h Handler) ListAuditEvents(ctx context.Context, req gen.ListAuditEventsRequestObject) (gen.ListAuditEventsResponseObject, error) {
	actor, err := ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	p := req.Params
	f := Filter{EntityType: deref(p.EntityType), EntityID: deref(p.EntityId), ActorID: deref(p.ActorId), EventType: deref(p.EventType)}
	if p.From != nil {
		f.From = *p.From
	}
	if p.To != nil {
		f.To = *p.To
	}
	if p.BeforeId != nil {
		f.BeforeID = *p.BeforeId
	}
	if p.Limit != nil {
		f.Limit = *p.Limit
	}
	var page Page
	err = h.Writer.DB.WithTx(ctx, func(q *pggen.Queries) error {
		var err error
		if page, err = Query(ctx, q, f); err != nil {
			return err
		}
		_, err = h.Writer.Record(ctx, q, Event{
			Actor: actor, Purpose: deref(p.Purpose), EntityType: "events", EventType: EventAuditEventsViewed,
			Payload: map[string]any{"filter": p, "returned": len(page.Events)},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := gen.ListAuditEvents200JSONResponse{Events: make([]gen.AuditEvent, 0, len(page.Events))}
	if page.NextBeforeID > 0 {
		out.NextBeforeId = &page.NextBeforeID
	}
	for i := range page.Events {
		ev, err := toAPI(&page.Events[i])
		if err != nil {
			return nil, err
		}
		out.Events = append(out.Events, ev)
	}
	return out, nil
}

func toAPI(r *Row) (gen.AuditEvent, error) {
	var payload map[string]any
	if err := json.Unmarshal(r.Payload, &payload); err != nil {
		return gen.AuditEvent{}, errors.Join(errors.New("audit: stored payload is not a JSON object"), err)
	}
	return gen.AuditEvent{
		Id: r.ID, Ts: r.TS.UTC(), ActorType: gen.AuditEventActorType(r.ActorType), ActorId: r.ActorID,
		Realm: r.Realm, Purpose: r.Purpose, EntityType: r.EntityType, EntityId: r.EntityID,
		EventType: r.EventType, Payload: payload, PrevHash: r.PrevHash, Hash: r.Hash,
	}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// VerifyHandler serves GET /v1/audit/verify (apiserver.AuditVerifyHandler,
// WP-27): the month verified on request and recorded in the chain.
type VerifyHandler struct {
	Verifier *ChainVerifier
}

var _ apiserver.AuditVerifyHandler = VerifyHandler{}

// VerifyAuditChain verifies one month and records the verification.
func (h VerifyHandler) VerifyAuditChain(ctx context.Context, req gen.VerifyAuditChainRequestObject) (gen.VerifyAuditChainResponseObject, error) {
	actor, err := ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	month, err := time.Parse("2006-01", req.Params.Month)
	if err != nil {
		return nil, httpx.Refuse(http.StatusBadRequest, httpx.SlugValidation, "month is not YYYY-MM",
			core.Fieldf("month", "%q is not a UTC month YYYY-MM", req.Params.Month))
	}
	res, at, err := h.Verifier.VerifyMonth(ctx, actor, month, ViaRequest)
	if err != nil {
		return nil, err
	}
	out := gen.VerifyAuditChain200JSONResponse{Month: res.Month, Rows: res.Rows, Intact: res.Broken == nil, VerifiedAt: at.UTC()}
	if res.Rows > 0 {
		out.FirstId, out.LastId, out.LastHash = &res.FirstID, &res.LastID, &res.LastHash
	}
	if res.AnchoredTo != "" {
		out.AnchoredTo = &res.AnchoredTo
	}
	if b := res.Broken; b != nil {
		out.Broken = &gen.AuditChainBreak{Id: b.ID, Ts: b.TS.UTC(), Reason: gen.AuditChainBreakReason(b.Reason), Want: &b.Want, Got: &b.Got}
	}
	return out, nil
}
