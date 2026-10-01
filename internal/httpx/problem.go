package httpx

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/rootxkit/uspace-core/core"
)

// ProblemTypeBase prefixes every problem type (decision M28).
const ProblemTypeBase = "https://schemas.uspace.ge/problems/"

// MaxProblemErrors caps Problem.Errors; beyond it Truncated is true.
const MaxProblemErrors = 100

// ProblemContentType is the media type of every error body.
const ProblemContentType = "application/problem+json"

// Slugs used by this package.
const (
	SlugValidation   = "validation"
	SlugBodyTooLarge = "body_too_large"
	SlugRateLimited  = "rate_limited"
	SlugNotFound     = "not_found"
	SlugMethod       = "method_not_allowed"
	SlugInternal     = "internal"
)

// FieldProblem is one entry of Problem.Errors.
type FieldProblem struct {
	Field  string `json:"field"`
	Reason string `json:"reason"`
}

// Problem is the RFC 9457 body every endpoint returns on error, in the
// shape of uspace-lab schemas/common/problem/v1 and the Problem schema
// of api/openapi.yaml.
type Problem struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Status    int            `json:"status"`
	Detail    string         `json:"detail,omitempty"`
	Instance  string         `json:"instance,omitempty"`
	Errors    []FieldProblem `json:"errors"`
	Truncated bool           `json:"truncated,omitempty"`
}

var slugPattern = regexp.MustCompile(`^[a-z_]+$`)

// NewProblem builds a problem with slug (the counter or refusal name)
// and the field errors, capped at MaxProblemErrors. A slug outside
// [a-z_]+ is a programming error; it is replaced by "internal" so the
// body still validates against the schema.
func NewProblem(status int, slug, title, detail string, errs ...*core.FieldError) *Problem {
	if !slugPattern.MatchString(slug) {
		slug = SlugInternal
	}
	if title == "" {
		title = http.StatusText(status)
	}
	p := &Problem{Type: ProblemTypeBase + slug, Title: title, Status: status, Detail: detail, Errors: []FieldProblem{}}
	for i, fe := range errs {
		if i == MaxProblemErrors {
			p.Truncated = true
			break
		}
		p.Errors = append(p.Errors, FieldProblem{Field: fe.Field, Reason: fe.Reason})
	}
	return p
}

// Slug is the last path segment of the problem type.
func (p *Problem) Slug() string { return p.Type[len(ProblemTypeBase):] }

// Write sends p as application/problem+json. Instance defaults to the
// request path.
func (p *Problem) Write(w http.ResponseWriter, r *http.Request) {
	if p.Instance == "" && r != nil {
		p.Instance = r.URL.Path
	}
	w.Header().Set("Content-Type", ProblemContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// WriteError maps err onto a problem and writes it: field errors are a
// 400 validation problem listing every field, an oversized body is 413,
// anything else is a 500 that does not echo the error text.
func WriteError(w http.ResponseWriter, r *http.Request, err error) {
	ProblemFromError(err).Write(w, r)
}

// ProblemFromError is the mapping WriteError uses.
func ProblemFromError(err error) *Problem {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return NewProblem(http.StatusRequestEntityTooLarge, SlugBodyTooLarge, "", "request body exceeds the limit of this route",
			core.Fieldf("body", "longer than %d bytes", mbe.Limit))
	}
	if fes := fieldErrors(err); len(fes) > 0 {
		return NewProblem(http.StatusBadRequest, SlugValidation, "Invalid request", "", fes...)
	}
	return NewProblem(http.StatusInternalServerError, SlugInternal, "", "")
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
	return nil
}
