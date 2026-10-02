package switches

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/sources"
)

// Handler serves /v1/sources* (admin).
type Handler struct {
	Service *Service
	Status  *sources.StatusStore
	// StaleAfter is SOURCE_STATUS_STALE_S: an adapter whose last status
	// is older is silent, and its sources are stale.
	StaleAfter time.Duration
	Now        func() time.Time
}

func (h Handler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func controlOut(c sources.Control) gen.SourceControl {
	return gen.SourceControl{
		SourceType: gen.SourceType(c.SourceType), InstanceId: c.InstanceID, Enabled: c.Enabled, Reason: c.Reason,
		Actor: c.Actor, ChangedAt: c.ChangedAt, Version: int64(c.Version),
	}
}

func resultOut(r Result) gen.SourceSwitchResult {
	return gen.SourceSwitchResult{Control: controlOut(r.Control), Changed: r.Changed, Epoch: r.Epoch, Version: int64(r.Version)}
}

func (h Handler) switchSource(ctx context.Context, sourceType string, instanceID *string, body *gen.SourceSwitchInput) (Result, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return Result{}, err
	}
	if body == nil {
		return Result{}, &core.FieldError{Field: "body", Reason: "required"}
	}
	return h.Service.Switch(ctx, actor, sourceType, instanceID, body.Enabled, body.Reason)
}

// SwitchSourceType switches a whole type.
func (h Handler) SwitchSourceType(ctx context.Context, req gen.SwitchSourceTypeRequestObject) (gen.SwitchSourceTypeResponseObject, error) {
	r, err := h.switchSource(ctx, string(req.SourceType), nil, req.Body)
	if err != nil {
		return nil, err
	}
	return gen.SwitchSourceType200JSONResponse(resultOut(r)), nil
}

// SwitchSourceInstance switches one instance.
func (h Handler) SwitchSourceInstance(ctx context.Context, req gen.SwitchSourceInstanceRequestObject) (gen.SwitchSourceInstanceResponseObject, error) {
	id := req.InstanceId
	r, err := h.switchSource(ctx, string(req.SourceType), &id, req.Body)
	if err != nil {
		return nil, err
	}
	return gen.SwitchSourceInstance200JSONResponse(resultOut(r)), nil
}

// ListSources answers every switch and every source the switches name or
// an adapter has reported, with its switch and its health.
func (h Handler) ListSources(ctx context.Context, _ gen.ListSourcesRequestObject) (gen.ListSourcesResponseObject, error) {
	d, err := h.Service.Overview(ctx)
	if err != nil {
		return nil, err
	}
	now := h.now()
	out := gen.SourceOverview{Epoch: d.Epoch, Version: int64(d.Version), DefaultDeny: d.DefaultDeny,
		Controls: make([]gen.SourceControl, 0, len(d.Controls)), Sources: []gen.SourceView{}}
	byKey := map[[2]string]sources.Control{}
	pairs := map[[2]string]bool{}
	for _, c := range d.Controls {
		out.Controls = append(out.Controls, controlOut(c))
		inst := ""
		if c.InstanceID != nil {
			inst = *c.InstanceID
			pairs[[2]string{c.SourceType, inst}] = true
		}
		byKey[[2]string{c.SourceType, inst}] = c
	}
	if h.Status != nil {
		for _, p := range h.Status.Instances() {
			if slices.Contains(sources.Types, p[0]) {
				pairs[p] = true
			}
		}
	}
	keys := make([][2]string, 0, len(pairs))
	for p := range pairs {
		keys = append(keys, p)
	}
	slices.SortFunc(keys, func(a, b [2]string) int {
		if c := strings.Compare(a[0], b[0]); c != 0 {
			return c
		}
		return strings.Compare(a[1], b[1])
	})
	for _, p := range keys {
		inst := p[1]
		v := gen.SourceView{SourceType: gen.SourceType(p[0]), InstanceId: &inst, Switch: gen.SourceViewSwitchEnabled}
		dec := Decide(d, p[0], &inst)
		if !dec.Enabled {
			v.Switch = gen.SourceViewSwitchDisabled
			if dec.WhyDisabled != nil {
				by := gen.SourceViewDisabledBy(*dec.WhyDisabled)
				v.DisabledBy = &by
				row, ok := byKey[[2]string{p[0], inst}]
				if string(*dec.WhyDisabled) == "type" {
					row, ok = byKey[[2]string{p[0], ""}]
				}
				if ok && string(*dec.WhyDisabled) != "default_deny" {
					who, why := row.Actor, row.Reason
					v.DisabledByWho, v.DisabledReason = &who, &why
				}
			}
		}
		var st sources.Status
		have := false
		if h.Status != nil {
			st, have = h.Status.Get(p[0], &inst)
		}
		v.Health = gen.SourceViewHealth(sources.Health(st, have, now, h.StaleAfter))
		if have {
			age := now.Sub(st.ReceivedAt).Seconds()
			v.StatusAgeS, v.AgeS, v.LagS = &age, st.Body.AgeS, st.Body.LagS
			counters := make(map[string]int64, len(st.Body.Counters))
			for k, n := range st.Body.Counters {
				counters[k] = int64(n)
			}
			v.Counters = &counters
		}
		out.Sources = append(out.Sources, v)
	}
	return gen.ListSources200JSONResponse(out), nil
}
