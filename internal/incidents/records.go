package incidents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RecordsScope is the scope of the USSP service-record read (WP-2 table
// B; spec 02 F7).
const RecordsScope = "ussp.records"

// recordsPath is the national API path of one flight's service record
// on a USSP (spec 02 F7 "Service records"). Its body is not defined by
// any contract this repository pins (uspace-ussp has none yet): the
// record is kept verbatim, as an opaque JSON object with its hash.
const recordsPath = "/v1/records/flights/"

// TokenSource hands out an ecosystem token for the host of baseURL with
// the scopes (tokens.Client).
type TokenSource interface {
	Token(ctx context.Context, baseURL string, scopes ...string) (string, error)
}

// Records fetches USSP service records on demand.
type Records struct {
	// Tokens is nil when no client is configured: every record is then
	// unavailable with that reason.
	Tokens TokenSource
	HTTP   *http.Client
	// Timeout bounds one fetch; MaxBytes one body.
	Timeout  time.Duration
	MaxBytes int64
}

// ErrNoRecordsClient is the reason without a token client.
var ErrNoRecordsClient = errors.New("no client for ussp.records (RECORDS_CLIENT_SECRET_FILE)")

// CheckBaseURL accepts an https URL without userinfo, query or fragment,
// or http to a loopback host (the lab and tests).
func CheckBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("base_url %q is not an absolute URL without userinfo, query or fragment", raw)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); (ip == nil || !ip.IsLoopback()) && u.Hostname() != "localhost" {
			return nil, fmt.Errorf("base_url %q: http only to a loopback host", raw)
		}
	default:
		return nil, fmt.Errorf("base_url %q is not https", raw)
	}
	return u, nil
}

// ParseUSSPList reads the USSP list as cis/ussp_list/v1 carries it (the
// CISP's schema: ussps[].ussp_id, ussps[].base_url) into ussp_id ->
// base_url. Entries without either are skipped; the first of a repeated
// id wins (the CIS validated the list as unique).
func ParseUSSPList(payload []byte) (map[string]string, error) {
	var doc struct {
		USSPs []struct {
			USSPID  string `json:"ussp_id"`
			BaseURL string `json:"base_url"`
		} `json:"ussps"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil, fmt.Errorf("ussp list: %w", err)
	}
	out := make(map[string]string, len(doc.USSPs))
	for _, u := range doc.USSPs {
		if u.USSPID == "" || u.BaseURL == "" {
			continue
		}
		if _, dup := out[u.USSPID]; !dup {
			out[u.USSPID] = u.BaseURL
		}
	}
	return out, nil
}

// ParseRecord accepts a service record body: one JSON object of at most
// maxBytes. It is returned compacted, so the pack holds it in one form.
func ParseRecord(body []byte, maxBytes int64) (json.RawMessage, error) {
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("record larger than %d bytes", maxBytes)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return nil, errors.New("record is not a JSON object")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, trimmed); err != nil {
		return nil, fmt.Errorf("record: %w", err)
	}
	return buf.Bytes(), nil
}

// Fetch reads one flight's service record from the USSP at baseURL with
// a token of scope ussp.records whose audience is that host. Every
// failure is an error naming what failed (it becomes the manifest's
// reason); nothing is retried here.
func (r *Records) Fetch(ctx context.Context, baseURL, flightID string) (json.RawMessage, error) {
	if r.Tokens == nil {
		return nil, ErrNoRecordsClient
	}
	u, err := CheckBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if flightID == "" || len(flightID) > 256 {
		return nil, errors.New("flight id is empty or longer than 256")
	}
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	tok, err := r.Tokens.Token(ctx, baseURL, RecordsScope)
	if err != nil {
		return nil, fmt.Errorf("token for %s: %w", u.Host, err)
	}
	target := strings.TrimRight(u.String(), "/") + recordsPath + url.PathEscape(flightID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	hc := r.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u.Host+recordsPath+"{id}", err)
	}
	defer func() { _ = resp.Body.Close() }()
	maxBytes := r.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read record: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the USSP answered %d", resp.StatusCode)
	}
	return ParseRecord(body, maxBytes)
}
