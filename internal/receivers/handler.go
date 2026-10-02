package receivers

import (
	"context"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
)

var noStore = "no-store"

// Handler serves the admin operations of /v1/rid/receivers* (generated
// strict server).
type Handler struct {
	Service *Service
}

func configOut(c Config) gen.RIDReceiverConfig {
	out := gen.RIDReceiverConfig{
		BatchIntervalMs: c.BatchIntervalMS, BacklogCap: c.BacklogCap, HeartbeatIntervalS: c.HeartbeatIntervalS,
		PositionToleranceM: c.PositionToleranceM,
	}
	if c.ReportingFields != nil {
		fs := make([]gen.RIDReportingField, 0, len(c.ReportingFields))
		for _, f := range c.ReportingFields {
			fs = append(fs, gen.RIDReportingField(f))
		}
		out.ReportingFields = &fs
	}
	return out
}

func configIn(c *gen.RIDReceiverConfig) Config {
	if c == nil {
		return Config{}
	}
	out := Config{
		BatchIntervalMS: c.BatchIntervalMs, BacklogCap: c.BacklogCap, HeartbeatIntervalS: c.HeartbeatIntervalS,
		PositionToleranceM: c.PositionToleranceM,
	}
	if c.ReportingFields != nil {
		out.ReportingFields = make([]string, 0, len(*c.ReportingFields))
		for _, f := range *c.ReportingFields {
			out.ReportingFields = append(out.ReportingFields, string(f))
		}
	}
	return out
}

func positionOut(p *Position) *gen.RIDPosition {
	if p == nil {
		return nil
	}
	return &gen.RIDPosition{LatDeg: p.LatDeg, LonDeg: p.LonDeg, AltHaeM: p.AltHAEM}
}

func receiverOut(r *Receiver) gen.RIDReceiver {
	return gen.RIDReceiver{
		Id: r.ID, Label: r.Name, LatDeg: r.LatDeg, LonDeg: r.LonDeg, Owner: gen.RIDReceiverOwner(r.Owner),
		OwnerName: r.OwnerName, Status: gen.RIDReceiverStatus(r.Status), DisabledBy: r.DisabledBy,
		DisabledReason: r.DisabledReason, DisabledAt: r.DisabledAt, KeyGeneration: r.KeyGeneration,
		PreviousKeyValidUntil: r.PreviousKeyValidUntil, LastSeenAt: r.LastSeenAt, LastPosition: positionOut(r.LastPosition),
		PositionDeviationM: r.PositionDeviationM, PositionDeviations: r.PositionDeviations, Firmware: r.Firmware,
		Config: configOut(r.Config), Version: r.Version, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
		UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy,
	}
}

func createdOut(r *Receiver, c Credentials) gen.RIDReceiverCreated {
	return gen.RIDReceiverCreated{
		Receiver: receiverOut(r),
		Credentials: gen.RIDReceiverCredentials{
			Generation: c.Generation, BearerKey: c.BearerKey, HmacSecretHex: c.HMACSecretHex,
			SignatureHeader: gen.RIDReceiverCredentialsSignatureHeaderXReportSignature,
		},
	}
}

func bodyRequired() error { return &core.FieldError{Field: "body", Reason: "required"} }

// ListRIDReceivers answers one page.
func (h Handler) ListRIDReceivers(ctx context.Context, req gen.ListRIDReceiversRequestObject) (gen.ListRIDReceiversResponseObject, error) {
	limit := 100
	if req.Params.Limit != nil {
		limit = *req.Params.Limit
	}
	after := ""
	if req.Params.After != nil {
		after = *req.Params.After
	}
	rs, next, err := h.Service.List(ctx, after, limit)
	if err != nil {
		return nil, err
	}
	out := gen.RIDReceiverList{Receivers: make([]gen.RIDReceiver, 0, len(rs))}
	for i := range rs {
		out.Receivers = append(out.Receivers, receiverOut(&rs[i]))
	}
	if next != "" {
		out.NextAfter = &next
	}
	return gen.ListRIDReceivers200JSONResponse(out), nil
}

// CreateRIDReceiver registers a receiver and shows its keys once.
func (h Handler) CreateRIDReceiver(ctx context.Context, req gen.CreateRIDReceiverRequestObject) (gen.CreateRIDReceiverResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	r, creds, err := h.Service.Create(ctx, actor, NewReceiver{
		ID: b.Id, Name: b.Label, LatDeg: b.LatDeg, LonDeg: b.LonDeg, Owner: string(b.Owner), OwnerName: b.OwnerName,
		Config: configIn(b.Config),
	})
	if err != nil {
		return nil, err
	}
	return gen.CreateRIDReceiver201JSONResponse{
		Body: createdOut(&r, creds), Headers: gen.CreateRIDReceiver201ResponseHeaders{CacheControl: &noStore},
	}, nil
}

// GetRIDReceiver answers one receiver.
func (h Handler) GetRIDReceiver(ctx context.Context, req gen.GetRIDReceiverRequestObject) (gen.GetRIDReceiverResponseObject, error) {
	r, err := h.Service.Get(ctx, req.ReceiverId)
	if err != nil {
		return nil, err
	}
	return gen.GetRIDReceiver200JSONResponse(receiverOut(&r)), nil
}

// UpdateRIDReceiver changes a receiver's details.
func (h Handler) UpdateRIDReceiver(ctx context.Context, req gen.UpdateRIDReceiverRequestObject) (gen.UpdateRIDReceiverResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	p := Patch{Name: b.Label, LatDeg: b.LatDeg, LonDeg: b.LonDeg, OwnerName: b.OwnerName}
	if b.Owner != nil {
		o := string(*b.Owner)
		p.Owner = &o
	}
	if b.Config != nil {
		c := configIn(b.Config)
		p.Config = &c
	}
	r, err := h.Service.Update(ctx, actor, req.ReceiverId, p)
	if err != nil {
		return nil, err
	}
	return gen.UpdateRIDReceiver200JSONResponse(receiverOut(&r)), nil
}

// DeleteRIDReceiver deletes a receiver and its key-set entry.
func (h Handler) DeleteRIDReceiver(ctx context.Context, req gen.DeleteRIDReceiverRequestObject) (gen.DeleteRIDReceiverResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	if err := h.Service.Delete(ctx, actor, req.ReceiverId, req.Params.Reason); err != nil {
		return nil, err
	}
	return gen.DeleteRIDReceiver204Response{}, nil
}

// SetRIDReceiverStatus disables or enables a receiver.
func (h Handler) SetRIDReceiverStatus(ctx context.Context, req gen.SetRIDReceiverStatusRequestObject) (gen.SetRIDReceiverStatusResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	b := req.Body
	if b == nil {
		return nil, bodyRequired()
	}
	r, err := h.Service.SetStatus(ctx, actor, req.ReceiverId, string(b.Status), b.Reason)
	if err != nil {
		return nil, err
	}
	return gen.SetRIDReceiverStatus200JSONResponse(receiverOut(&r)), nil
}

// RotateRIDReceiverKeys issues a new key generation and shows it once.
func (h Handler) RotateRIDReceiverKeys(ctx context.Context, req gen.RotateRIDReceiverKeysRequestObject) (gen.RotateRIDReceiverKeysResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	var grace *time.Duration
	if req.Body != nil && req.Body.GraceS != nil {
		g := time.Duration(*req.Body.GraceS) * time.Second
		grace = &g
	}
	r, creds, err := h.Service.Rotate(ctx, actor, req.ReceiverId, grace)
	if err != nil {
		return nil, err
	}
	return gen.RotateRIDReceiverKeys200JSONResponse{
		Body: createdOut(&r, creds), Headers: gen.RotateRIDReceiverKeys200ResponseHeaders{CacheControl: &noStore},
	}, nil
}
