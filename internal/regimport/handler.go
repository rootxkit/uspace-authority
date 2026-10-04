package regimport

import (
	"context"
	"io"
	"net/http"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
)

// SlugRefused is the problem slug of an import refused whole for its
// records' problems.
const SlugRefused = "import_refused"

// Handler serves POST /v1/registry/import.
type Handler struct {
	Service *Service
}

// ImportRegistry reads the body (CSV or JSON, by its Content-Type),
// runs the import or the dry run and answers its report; an import with
// problems is 422 naming every one by record and field.
func (h Handler) ImportRegistry(ctx context.Context, req gen.ImportRegistryRequestObject) (gen.ImportRegistryResponseObject, error) {
	actor, err := audit.ActorOf(ctx)
	if err != nil {
		return nil, err
	}
	var body []byte
	var format string
	switch {
	case req.JSONBody != nil:
		body, format = *req.JSONBody, FormatJSON
	case req.Body != nil:
		limit := h.Service.MaxBytes
		if limit <= 0 {
			limit = 64 << 20
		}
		if body, err = io.ReadAll(io.LimitReader(req.Body, int64(limit)+1)); err != nil {
			return nil, err
		}
		format = FormatCSV
	default:
		return nil, httpx.Refuse(http.StatusUnsupportedMediaType, "unsupported_media_type", "",
			core.Fieldf("Content-Type", "must be text/csv or application/json"))
	}
	dry := req.Params.DryRun != nil && *req.Params.DryRun
	rep, err := h.Service.Run(ctx, Request{Kind: string(req.Params.Kind), Format: format, Body: body, DryRun: dry, Origin: OriginUpload}, actor)
	if err != nil {
		return nil, err
	}
	if !rep.DryRun && len(rep.Problems) > 0 {
		return nil, httpx.Refuse(http.StatusUnprocessableEntity, SlugRefused,
			"the export was imported not at all: every problem is listed by record and field; fix the export or the rules file and import again",
			rep.Problems...)
	}
	return gen.ImportRegistry200JSONResponse(ReportBody(&rep)), nil
}

// ReportBody is the report as the contract states it.
func ReportBody(rep *Report) gen.RegistryImportReport {
	out := gen.RegistryImportReport{
		Kind: gen.RegistryImportKind(rep.Kind), DryRun: rep.DryRun, Applied: rep.Applied(), Records: rep.Records,
		Created: rep.Created, Updated: rep.Updated, Unchanged: rep.Unchanged, RulesVersion: rep.RulesVersion,
		ContentSha256: rep.SHA256, Problems: []gen.FieldProblem{}, Outcomes: []gen.RegistryImportOutcome{},
	}
	if rep.Version > 0 {
		v := rep.Version
		out.RegistryVersion = &v
	}
	for i, p := range rep.Problems {
		if i == httpx.MaxProblemErrors {
			t := true
			out.ProblemsTruncated = &t
			break
		}
		out.Problems = append(out.Problems, gen.FieldProblem{Field: p.Field, Reason: p.Reason})
	}
	for i := range rep.Outcomes {
		if i == MaxReportOutcomes {
			t := true
			out.OutcomesTruncated = &t
			break
		}
		o := &rep.Outcomes[i]
		g := gen.RegistryImportOutcome{Record: o.Record, SourceId: o.SourceRef, Action: gen.RegistryImportOutcomeAction(o.Action),
			Status: gen.RegistryStatus(o.Status)}
		if o.EntityID != "" && (!rep.DryRun || o.Action != registry.ImportCreated) {
			id := o.EntityID
			g.EntityId = &id
		}
		if len(o.Fields) > 0 {
			f := append([]string(nil), o.Fields...)
			g.Fields = &f
		}
		out.Outcomes = append(out.Outcomes, g)
	}
	return out
}
