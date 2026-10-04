package intents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3548"

	"github.com/rootxkit/uspace-authority/internal/dp"
	"github.com/rootxkit/uspace-authority/internal/dp/utmapi"
)

// DSS answers the operational intent reference query (F3548
// queryOperationalIntentReferences).
type DSS interface {
	Query(ctx context.Context, aoi f3548.Volume4D) ([]f3548.OperationalIntentReference, error)
}

// ErrNoTokens is every DSS query of a detector without a client secret:
// refused locally, and the detector says dss_unconfigured.
var ErrNoTokens = errors.New("no client secret for the detector's DSS reads (DETECT_CLIENT_SECRET_FILE)")

// Client queries the DSS through the client generated from the pinned
// contract (internal/dp/utmapi, api/clients/dss-utm.yaml), with a bearer
// token for the DSS's host granting utm.conformance_monitoring_sa (Q-A5),
// a bounded body and a bounded number of references.
type Client struct {
	HTTP   *http.Client
	Tokens dp.Tokens
	// DSS is the DSS base URL (F3548 is under /dss/v1).
	DSS string
	// MaxBody bounds one answer (default 1 MiB); MaxRefs the references
	// taken from it (default DefaultMaxRefs).
	MaxBody int64
	MaxRefs int
}

var _ DSS = (*Client)(nil)

// Query is POST /dss/v1/operational_intent_references/query for aoi.
func (c *Client) Query(ctx context.Context, aoi f3548.Volume4D) ([]f3548.OperationalIntentReference, error) {
	if _, err := dp.CheckBaseURL(c.DSS); err != nil {
		return nil, err
	}
	hc := c.HTTP
	if hc == nil {
		hc = dp.NoRedirectClient()
	}
	sc, err := utmapi.NewClient(strings.TrimSuffix(c.DSS, "/"), utmapi.WithHTTPClient(hc))
	if err != nil {
		return nil, err
	}
	resp, err := sc.QueryOperationalIntentReferences(ctx, f3548.QueryOperationalIntentReferenceParameters{AreaOfInterest: &aoi}, c.auth)
	if err != nil {
		return nil, err
	}
	body, err := c.read(resp)
	if err != nil {
		return nil, err
	}
	return ParseQueryResponse(body, c.maxRefs())
}

func (c *Client) maxRefs() int {
	if c.MaxRefs > 0 {
		return c.MaxRefs
	}
	return DefaultMaxRefs
}

// auth adds the bearer token for the DSS (aud its host, M18).
func (c *Client) auth(ctx context.Context, req *http.Request) error {
	if c.Tokens == nil {
		return ErrNoTokens
	}
	tok, err := c.Tokens.Token(ctx, c.DSS, string(f3548.ScopeConformanceMonitoringForSituationalAwareness))
	if err != nil {
		return fmt.Errorf("token for the DSS: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	return nil
}

// read takes the body of resp, at most MaxBody bytes, and refuses any
// status but 200.
func (c *Client) read(resp *http.Response) ([]byte, error) {
	defer func() { _ = resp.Body.Close() }()
	limit := c.MaxBody
	if limit <= 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("query operational intents: read: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("query operational intents: %w (%d bytes)", dp.ErrTooLarge, limit)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &dp.HTTPError{Op: "query operational intents", Status: resp.StatusCode}
	}
	return body, nil
}

// DefaultMaxRefs bounds the references taken from one answer (E-10).
const DefaultMaxRefs = 1000

// maxIDBytes bounds every identifier and URL taken from an answer.
const maxIDBytes = 512

// ErrTooManyRefs is an answer with more references than the bound: it is
// refused whole, never cut, so a reference that would have matched is
// never silently left out.
var ErrTooManyRefs = errors.New("more operational intent references than the bound")

// ParseQueryResponse reads a QueryOperationalIntentReferenceResponse from
// untrusted bytes. uspace-core has no validating reader for it (a spec
// gap, WP-26 pull request): this one refuses invalid JSON, more than
// maxRefs references, and a reference without an id or with an
// identifier, manager or uss_base_url over maxIDBytes, a state that is
// not one of the four DSS states, a time that is not RFC3339 or an end
// before its start, naming the member. Unknown members are ignored (spec
// 02 §1). It never panics (FuzzParseQueryResponse).
func ParseQueryResponse(raw []byte, maxRefs int) ([]f3548.OperationalIntentReference, error) {
	if len(raw) > f3548.MaxMessageBytes {
		return nil, core.Fieldf("response", "is %d bytes; at most %d", len(raw), f3548.MaxMessageBytes)
	}
	// Count first, so an oversized list is refused before it is decoded.
	var shape struct {
		Refs []json.RawMessage `json:"operational_intent_references"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&shape); err != nil {
		return nil, core.Fieldf("response", "not a QueryOperationalIntentReferenceResponse")
	}
	if shape.Refs == nil {
		return nil, core.Fieldf("response.operational_intent_references", "required")
	}
	if len(shape.Refs) > maxRefs {
		return nil, fmt.Errorf("%w: %d, at most %d", ErrTooManyRefs, len(shape.Refs), maxRefs)
	}
	out := make([]f3548.OperationalIntentReference, 0, len(shape.Refs))
	for i, r := range shape.Refs {
		field := fmt.Sprintf("response.operational_intent_references[%d]", i)
		var ref f3548.OperationalIntentReference
		if err := json.Unmarshal(r, &ref); err != nil {
			return nil, core.Fieldf(field, "not an OperationalIntentReference")
		}
		if err := checkRef(&ref); err != nil {
			var fe *core.FieldError
			if errors.As(err, &fe) {
				return nil, core.Fieldf(field+"."+fe.Field, "%s", fe.Reason)
			}
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

// checkRef checks the members the matching rests on.
func checkRef(r *f3548.OperationalIntentReference) error {
	switch {
	case r.Id == "" || len(r.Id) > maxIDBytes:
		return core.Fieldf("id", "required, at most %d bytes", maxIDBytes)
	case len(r.Manager) > maxIDBytes:
		return core.Fieldf("manager", "longer than %d bytes", maxIDBytes)
	case len(r.UssBaseUrl) > maxIDBytes:
		return core.Fieldf("uss_base_url", "longer than %d bytes", maxIDBytes)
	case !slices.Contains(f3548.DSSStates, r.State):
		return core.Fieldf("state", "%q is not one of the four DSS states", string(r.State))
	case r.TimeStart.Format != f3548.RFC3339 || r.TimeStart.Value.IsZero():
		return core.Fieldf("time_start", "required, RFC3339")
	case r.TimeEnd.Format != f3548.RFC3339 || r.TimeEnd.Value.IsZero():
		return core.Fieldf("time_end", "required, RFC3339")
	case r.TimeEnd.Value.Before(r.TimeStart.Value):
		return core.Fieldf("time_end", "is before time_start")
	}
	return nil
}
