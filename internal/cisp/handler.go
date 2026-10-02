package cisp

import (
	"context"
	"time"

	"github.com/rootxkit/uspace-authority/api/gen"
)

// DefaultListLimit is GET /v1/publications' default page.
const DefaultListLimit = 100

// Handler serves GET /v1/publications (apiserver.CISPHandler).
type Handler struct {
	Store      OutboxStore
	Subscriber *Subscriber
	Heartbeat  *Heartbeat
	// Configured is false without CISP_BASE_URL.
	Configured bool
}

// ListPublications implements apiserver.CISPHandler.
func (h Handler) ListPublications(ctx context.Context, req gen.ListPublicationsRequestObject) (gen.ListPublicationsResponseObject, error) {
	f := ListFilter{Limit: DefaultListLimit}
	if req.Params.Dataset != nil {
		f.Dataset = Dataset(*req.Params.Dataset)
	}
	if req.Params.State != nil {
		f.State = string(*req.Params.State)
	}
	if req.Params.Limit != nil {
		f.Limit = *req.Params.Limit
	}
	rows, err := h.Store.List(ctx, f)
	if err != nil {
		return nil, err
	}
	out := gen.PublicationStatus{
		CispConfigured: h.Configured, Publications: make([]gen.PublicationOutboxRow, 0, len(rows)), Cache: []gen.CISCacheState{},
	}
	for i := range rows {
		out.Publications = append(out.Publications, outboxRow(&rows[i]))
	}
	if h.Subscriber != nil {
		states := h.Subscriber.State()
		for i := range states {
			out.Cache = append(out.Cache, cacheState(&states[i]))
		}
		sub := h.Subscriber.Subscription()
		out.Subscription = gen.CISSubscriptionState{Enabled: sub.Enabled, CallbackUrl: opt(sub.CallbackURL),
			SubscriptionId: opt(sub.ID), Status: opt(sub.Status), LastError: opt(sub.LastError)}
	}
	if h.Heartbeat != nil {
		hb := h.Heartbeat.State()
		out.Heartbeat = gen.PublisherHeartbeatState{Enabled: hb.Enabled, IntervalS: hb.IntervalS, LastSuccessAt: hb.LastSuccessAt,
			LastStatus: hb.LastStatus, LastError: opt(hb.LastError), ConsecutiveFailures: hb.ConsecutiveFailures}
	}
	return gen.ListPublications200JSONResponse(out), nil
}

func outboxRow(r *OutboxView) gen.PublicationOutboxRow {
	out := gen.PublicationOutboxRow{
		Id: r.ID, Dataset: gen.PublicationOutboxRowDataset(r.Dataset), Version: r.Version, PayloadHash: r.PayloadHash,
		FeatureCount: r.FeatureCount, ContentType: r.ContentType, State: gen.PublicationOutboxRowState(r.State), Attempts: r.Attempts,
		SignatureKid: r.SignatureKID, SignedAt: utc(r.SignedAt), NextRetryAt: utc(r.NextRetryAt), CispVersion: r.CISPVersion,
		ConflictVersion: r.ConflictVersion, LastAttemptAt: utc(r.LastAttemptAt), LastStatus: r.LastStatus, LastError: r.LastError,
		AcknowledgedAt: utc(r.AcknowledgedAt), CreatedAt: r.CreatedAt.UTC(), CreatedBy: r.CreatedBy, StateChangedAt: r.StateChangedAt.UTC(),
	}
	if r.State == StatePending || r.State == StateSent {
		age := r.AgeS
		out.AgeS = &age
	}
	return out
}

func cacheState(c *CacheState) gen.CISCacheState {
	out := gen.CISCacheState{
		Dataset: gen.CISCacheStateDataset(c.Dataset), CisVersion: c.Version, CisAgeS: c.AgeS, Stale: c.Stale,
		Etag: opt(c.ETag), CisUpdatedAt: utc(c.UpdatedAt), FetchedAt: utc(c.FetchedAt), CheckedAt: utc(c.CheckedAt),
		FeatureCount: c.FeatureCount, HeldVersion: c.HeldVersion, HeldReason: opt(c.HeldReason),
		RefusedVersion: c.RefusedVersion, RefusedReason: opt(c.RefusedReason), LastError: opt(c.LastError),
	}
	return out
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
