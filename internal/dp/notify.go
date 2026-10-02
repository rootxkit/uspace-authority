package dp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/f3411"

	"github.com/rootxkit/uspace-authority/internal/dp/ridapi"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// Verifier verifies a bearer token (uspace-core auth.Verifier, or a
// lazily built one).
type Verifier interface {
	Verify(ctx context.Context, token string) (auth.Claims, error)
}

// PatternNotification is the one F3411 route dp-poller serves, as the
// generated server registers it (api/clients/dss-rid.yaml
// postIdentificationServiceArea).
const PatternNotification = "POST /uss/identification_service_areas/{id}"

// Counters of the notification route (E-09, E-01: every refusal named).
const (
	CounterNotifyAccepted      = "notifications_accepted"
	CounterNotifyNoToken       = "notifications_refused_no_token"
	CounterNotifyBadToken      = "notifications_refused_token"
	CounterNotifyUnavailable   = "notifications_refused_verifier_unavailable"
	CounterNotifyScope         = "notifications_refused_scope"
	CounterNotifyTooLarge      = "notifications_refused_too_large"
	CounterNotifyMalformed     = "notifications_refused_malformed"
	CounterNotifyNotOwner      = "notifications_refused_not_owner"
	CounterNotifyIDMismatch    = "notifications_refused_id_mismatch"
	CounterNotifyDeletedISA    = "notifications_isa_deleted"
	CounterNotifyUnknownDelete = "notifications_delete_of_unknown_isa"
)

// Notifications is POST /uss/identification_service_areas/{id}: the ISA
// change a Service Provider posts to every subscriber the DSS named
// (F3411: the DSS only lists them). The token is verified by the shared
// verifier (an allow-listed issuer: this system's, or the lab's in the
// lab; aud one of AUTHORITY_AUDIENCES; M6, M18) and must grant
// rid.service_provider; the service area's owner must be the token's
// subject (F3411 403: "not the owner of this Entity"). The route fails
// closed: no verifier, no admission.
type Notifications struct {
	Verifier Verifier
	ISAs     *ISAs
	// Known reports whether a subscription id is one of this system's.
	Known    func(id string) bool
	MaxBytes int64
	// Changed is told after every applied notification (the engine
	// reconciles at once).
	Changed  func()
	Counters *core.Counters
	Limiter  *logging.Limiter
}

var _ ridapi.ServerInterface = notificationServer{}

// notificationServer is the generated F3411 server interface of which
// only PostIdentificationServiceArea is mounted (Mount).
type notificationServer struct{ n *Notifications }

// errorResponse writes the F3411 ErrorResponse.
func errorResponse(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(f3411.ErrorResponse{Message: &message})
}

// notMounted answers the operations dp-poller does not serve (never
// reached: Mount registers one pattern).
func notMounted(w http.ResponseWriter) { errorResponse(w, http.StatusNotFound, "not served here") }

// SearchIdentificationServiceAreas is not served here.
func (notificationServer) SearchIdentificationServiceAreas(w http.ResponseWriter, _ *http.Request, _ f3411.SearchIdentificationServiceAreasParams) {
	notMounted(w)
}

// CreateSubscription is not served here.
func (notificationServer) CreateSubscription(w http.ResponseWriter, _ *http.Request, _ string) {
	notMounted(w)
}

// DeleteSubscription is not served here.
func (notificationServer) DeleteSubscription(w http.ResponseWriter, _ *http.Request, _ string, _ string) {
	notMounted(w)
}

// UpdateSubscription is not served here.
func (notificationServer) UpdateSubscription(w http.ResponseWriter, _ *http.Request, _ string, _ string) {
	notMounted(w)
}

// SearchFlights is not served here.
func (notificationServer) SearchFlights(w http.ResponseWriter, _ *http.Request, _ f3411.SearchFlightsParams) {
	notMounted(w)
}

// GetFlightDetails is not served here.
func (notificationServer) GetFlightDetails(w http.ResponseWriter, _ *http.Request, _ string) {
	notMounted(w)
}

// PostIdentificationServiceArea implements the route.
func (s notificationServer) PostIdentificationServiceArea(w http.ResponseWriter, r *http.Request, id string) {
	s.n.serve(w, r, id)
}

// keepOne is a ServeMux that registers only PatternNotification of the
// generated routes.
type keepOne struct{ *http.ServeMux }

// HandleFunc registers pattern when it is PatternNotification.
func (k keepOne) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	if pattern == PatternNotification {
		k.ServeMux.HandleFunc(pattern, h)
	}
}

// Mount registers the route on mux through the generated server.
func (n *Notifications) Mount(mux *http.ServeMux) {
	ridapi.HandlerWithOptions(notificationServer{n: n}, ridapi.StdHTTPServerOptions{
		BaseRouter: keepOne{mux},
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			n.inc(CounterNotifyMalformed)
			errorResponse(w, http.StatusBadRequest, "invalid request: "+err.Error())
		},
	})
}

func (n *Notifications) inc(name string) {
	if n.Counters != nil {
		n.Counters.Inc(name)
	}
}

// Bearer is the token of an Authorization: Bearer header, "" without
// one.
func Bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

// authenticate verifies the bearer and the scope; it writes the refusal
// and returns false when the request is not admitted.
func authenticate(w http.ResponseWriter, r *http.Request, v Verifier, scope string, inc func(string), counters [4]string,
	refuse func(http.ResponseWriter, int, string)) (auth.Claims, bool) {
	tok := Bearer(r)
	if tok == "" {
		inc(counters[0])
		refuse(w, http.StatusUnauthorized, "a bearer token is required")
		return auth.Claims{}, false
	}
	if v == nil {
		inc(counters[2])
		refuse(w, http.StatusServiceUnavailable, "token verification unavailable")
		return auth.Claims{}, false
	}
	cl, err := v.Verify(r.Context(), tok)
	if err != nil {
		var te *auth.TokenError
		if !errors.As(err, &te) {
			inc(counters[2])
			refuse(w, http.StatusServiceUnavailable, "token verification unavailable; retry")
			return auth.Claims{}, false
		}
		inc(counters[1])
		refuse(w, http.StatusUnauthorized, "token refused: "+te.Claim)
		return auth.Claims{}, false
	}
	if err := auth.RequireScope(cl, scope); err != nil {
		inc(counters[3])
		refuse(w, http.StatusForbidden, "the token does not grant "+scope)
		return auth.Claims{}, false
	}
	return cl, true
}

func (n *Notifications) serve(w http.ResponseWriter, r *http.Request, id string) {
	cl, ok := authenticate(w, r, n.Verifier, string(f3411.ScopeServiceProvider), n.inc,
		[4]string{CounterNotifyNoToken, CounterNotifyBadToken, CounterNotifyUnavailable, CounterNotifyScope}, errorResponse)
	if !ok {
		return
	}
	limit := n.MaxBytes
	if limit <= 0 {
		limit = 256 << 10
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		n.inc(CounterNotifyTooLarge)
		errorResponse(w, http.StatusRequestEntityTooLarge, "notification larger than the bound")
		return
	}
	p, err := ParseNotification(body)
	if err != nil {
		n.inc(CounterNotifyMalformed)
		errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}
	if p.ServiceArea != nil {
		if p.ServiceArea.Id != "" && p.ServiceArea.Id != id {
			n.inc(CounterNotifyIDMismatch)
			errorResponse(w, http.StatusBadRequest, "service_area.id is not the id of the path")
			return
		}
		if p.ServiceArea.Owner != cl.Subject {
			n.inc(CounterNotifyNotOwner)
			errorResponse(w, http.StatusForbidden, "the client identified in the access token is not the owner of this Entity")
			return
		}
	} else {
		owner, known := n.ISAs.Owner(id)
		switch {
		case known && owner != cl.Subject:
			n.inc(CounterNotifyNotOwner)
			errorResponse(w, http.StatusForbidden, "the client identified in the access token is not the owner of this Entity")
			return
		case !known:
			n.inc(CounterNotifyUnknownDelete)
		default:
			n.inc(CounterNotifyDeletedISA)
		}
	}
	for _, sub := range p.Subscriptions {
		if n.Known != nil && !n.Known(sub.SubscriptionId) {
			n.inc(CounterNotificationsUnsub)
		}
	}
	n.ISAs.Notify(id, p.ServiceArea, p.Extents)
	n.inc(CounterNotifyAccepted)
	if n.Limiter != nil {
		n.Limiter.Limited("dp_notification:"+cl.Subject).Info("ISA change notification applied",
			slog.String("uss_id", cl.Subject), slog.Bool("deleted", p.ServiceArea == nil))
	}
	if n.Changed != nil {
		n.Changed()
	}
	w.WriteHeader(http.StatusNoContent)
}

// maxNotificationSubscriptions bounds the subscriptions one
// notification lists (E-10).
const maxNotificationSubscriptions = 1000

// ParseNotification reads a PutIdentificationServiceAreaNotificationParameters
// from untrusted bytes: valid JSON of the F3411 shape, the service
// area's id, owner and uss_base_url bounded, its times RFC3339, at most
// maxNotificationSubscriptions subscriptions. It never panics
// (FuzzParseNotification).
func ParseNotification(raw []byte) (*f3411.PutIdentificationServiceAreaNotificationParameters, error) {
	var p f3411.PutIdentificationServiceAreaNotificationParameters
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, core.Fieldf("body", "not a PutIdentificationServiceAreaNotificationParameters")
	}
	if len(p.Subscriptions) > maxNotificationSubscriptions {
		return nil, core.Fieldf("subscriptions", "more than %d", maxNotificationSubscriptions)
	}
	if a := p.ServiceArea; a != nil {
		switch {
		case a.Id == "" || len(a.Id) > maxIDBytes:
			return nil, core.Fieldf("service_area.id", "required, at most %d bytes", maxIDBytes)
		case a.Owner == "" || len(a.Owner) > maxIDBytes:
			return nil, core.Fieldf("service_area.owner", "required, at most %d bytes", maxIDBytes)
		case len(a.UssBaseUrl) > 2048:
			return nil, core.Fieldf("service_area.uss_base_url", "longer than 2048 bytes")
		case a.TimeEnd.Format != f3411.RFC3339 || a.TimeStart.Format != f3411.RFC3339:
			return nil, core.Fieldf("service_area.time_end", "time_start and time_end must be RFC3339")
		}
		if _, err := CheckBaseURL(a.UssBaseUrl); err != nil && !errors.Is(err, ErrPlainHTTP) {
			return nil, core.Fieldf("service_area.uss_base_url", "not an absolute http(s) URL")
		}
	}
	if p.Extents != nil {
		if _, _, _, err := f3411.Volume4DToZonesEnvelope(*p.Extents); err != nil {
			return nil, err
		}
	}
	return &p, nil
}
