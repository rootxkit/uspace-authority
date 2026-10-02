package cisp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	coreauth "github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/cisp/cispclient"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/logging"
)

// The receiver's route (M1): served outside the generated server
// (x-cis-delivery in api/openapi.yaml).
const (
	NotificationsPath    = "/v1/cis/notifications"
	PatternNotifications = "POST " + NotificationsPath
	ContentTypeJOSE      = "application/jose"
	ChangeSchema         = "cis/change/v1"
)

// Receiver bounds (E-10).
const (
	// MaxNotificationBytes bounds the body (the contract's maxLength).
	MaxNotificationBytes = 256 << 10
	// JTITTL is how long a delivery id is remembered: longer than the
	// five minutes during which core's CompactVerifier accepts its iat,
	// plus the skew, so a replay inside that time is always caught.
	JTITTL = 10 * time.Minute
	// DefaultMaxLiveJTIs bounds the remembered delivery ids; beyond it
	// the receiver answers 503 (the CISP retries) and counts it.
	DefaultMaxLiveJTIs = 100_000
)

// Problem slugs of the receiver.
const (
	SlugUnsupportedMediaType = "unsupported_media_type"
	SlugStoreUnavailable     = "store_unavailable"
)

// pullReasons are the reasons that start a pull (M16): a publication and
// every restriction reason. subscription_test, republished and any reason
// this receiver does not know are acknowledged without a pull (the
// additive-enum rule of spec 04 §4).
var pullReasons = map[string]bool{
	"publication": true, "restriction_created": true, "restriction_activated": true,
	"restriction_extended": true, "restriction_ended": true, "restriction_cancelled": true,
	"restriction_expired": true,
}

// knownAckReasons are acknowledged without a pull and are not unknown.
var knownAckReasons = map[string]bool{"subscription_test": true, "republished": true}

// NotifySender is one allow-listed notification issuer.
type NotifySender struct {
	// ANSP is true for the ANSP's degraded direct delivery (M5), false
	// for the CISP.
	ANSP bool
}

// CompactVerifier verifies a compact delivery JWS (core's
// auth.CompactVerifier).
type CompactVerifier interface {
	Verify(ctx context.Context, token string) (coreauth.CompactClaims, json.RawMessage, error)
}

// PullURLChecker is the configured CISP's pull_url guard.
type PullURLChecker interface {
	CheckPullURL(raw string) (*url.URL, error)
}

// ReceiverConfig configures a Receiver.
type ReceiverConfig struct {
	Verifier CompactVerifier
	// Senders are the allow-listed issuers by iss (AUTHORITY_CIS_NOTIFY_ISSUERS).
	Senders map[string]NotifySender
	Store   CacheStore
	// PullURL guards a notification's pull_url (nil: never followed).
	PullURL     PullURLChecker
	Trigger     func(Dataset, Hint)
	MaxLiveJTIs int64
	Counters    *core.Counters
	Logger      *slog.Logger
	Limiter     *logging.Limiter
	Now         func() time.Time
}

// Receiver is POST /v1/cis/notifications.
type Receiver struct{ cfg ReceiverConfig }

// NewReceiver builds a Receiver.
func NewReceiver(cfg ReceiverConfig) *Receiver {
	if cfg.Counters == nil {
		cfg.Counters = &core.Counters{}
	}
	if cfg.Logger == nil {
		cfg.Logger = logging.Discard()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxLiveJTIs <= 0 {
		cfg.MaxLiveJTIs = DefaultMaxLiveJTIs
	}
	return &Receiver{cfg: cfg}
}

// Mount serves the receiver on mux.
func (rc *Receiver) Mount(mux *http.ServeMux) { mux.Handle(PatternNotifications, rc) }

// refusedLog logs a refused notification once per interval (the counter
// counts every one).
func (rc *Receiver) refusedLog() *slog.Logger {
	if rc.cfg.Limiter != nil {
		return rc.cfg.Limiter.Limited("cis-notification-refused")
	}
	return rc.cfg.Logger
}

// ServeHTTP verifies the delivery, remembers its id, and answers 204; a
// publication or restriction reason also starts a pull of its dataset
// (asynchronously: the CISP wants an answer within 2 s).
func (rc *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != ContentTypeJOSE {
		rc.cfg.Counters.Inc(CounterWebhookMalformed)
		rc.refusedLog().Warn("CIS notification refused: not application/jose", slog.String("content_type", short(r.Header.Get("Content-Type"))))
		httpx.NewProblem(http.StatusUnsupportedMediaType, SlugUnsupportedMediaType, "", "the body must be a compact JWS, "+ContentTypeJOSE).Write(w, r)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxNotificationBytes+1))
	if err != nil {
		rc.cfg.Counters.Inc(CounterWebhookMalformed)
		httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "", "the body could not be read").Write(w, r)
		return
	}
	if len(raw) > MaxNotificationBytes {
		rc.cfg.Counters.Inc(CounterWebhookMalformed)
		httpx.NewProblem(http.StatusRequestEntityTooLarge, httpx.SlugBodyTooLarge, "", "the notification is too large",
			core.Fieldf("body", "longer than %d bytes", MaxNotificationBytes)).Write(w, r)
		return
	}
	claims, body, err := rc.cfg.Verifier.Verify(ctx, strings.TrimSpace(string(raw)))
	if err != nil {
		rc.unauthorised(w, r, err)
		return
	}
	sender, ok := rc.cfg.Senders[claims.Issuer]
	if !ok {
		// The verifier's allow-list and Senders come from the same
		// configuration; a gap is refused, never trusted.
		rc.unauthorised(w, r, &coreauth.TokenError{Counter: coreauth.CounterRejectedIssuer, Claim: "iss", Reason: "not a configured sender"})
		return
	}
	ch, ds, ferr := decodeChange(body)
	if ferr != nil {
		rc.cfg.Counters.Inc(CounterWebhookMalformed)
		rc.refusedLog().Warn("CIS notification refused: not a "+ChangeSchema+" record", slog.String("issuer", claims.Issuer),
			slog.String("field", ferr.Field))
		httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "", "the notification is not a "+ChangeSchema+" record", ferr).Write(w, r)
		return
	}
	fresh, full, err := rc.cfg.Store.RememberJTI(ctx, claims.Issuer, claims.JTI, JTITTL, rc.cfg.MaxLiveJTIs)
	switch {
	case err != nil:
		rc.cfg.Counters.Inc(CounterWebhookStoreFailed)
		logging.Error(ctx, rc.cfg.Logger, "CIS notification not recorded", err)
		w.Header().Set("Retry-After", "5")
		httpx.NewProblem(http.StatusServiceUnavailable, SlugStoreUnavailable, "", "the delivery id cannot be recorded; retry").Write(w, r)
		return
	case full:
		rc.cfg.Counters.Inc(CounterWebhookJTIFull)
		w.Header().Set("Retry-After", "30")
		httpx.NewProblem(http.StatusServiceUnavailable, CounterWebhookJTIFull, "", "too many recent deliveries; retry").Write(w, r)
		return
	case !fresh:
		rc.cfg.Counters.Inc(CounterWebhookReplayed)
		rc.cfg.Logger.Info("CIS notification replayed; acknowledged without action",
			slog.String("issuer", claims.Issuer), slog.String("jti", claims.JTI))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	rc.cfg.Counters.Inc(CounterWebhooks)
	if sender.ANSP {
		rc.cfg.Counters.Inc(CounterANSPDirect)
	}
	log := rc.cfg.Logger.With(slog.String("issuer", claims.Issuer), slog.String("jti", claims.JTI),
		slog.String("dataset", string(ds)), slog.Int64("cis_version", ch.Version), slog.String("reason", string(ch.Reason)))
	if !pullReasons[string(ch.Reason)] {
		rc.cfg.Counters.Inc(CounterWebhookAckOnly)
		if !knownAckReasons[string(ch.Reason)] {
			rc.cfg.Counters.Inc(CounterWebhookUnknown)
		}
		log.Info("CIS notification acknowledged without a pull")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h := Hint{Version: ch.Version, ETag: ch.Etag, Issuer: claims.Issuer, At: rc.cfg.Now()}
	switch {
	case ch.PullUrl == "":
	case sender.ANSP:
		// The ANSP's direct delivery names its own resource; pulls go to
		// the configured CISP only.
		rc.cfg.Counters.Inc(CounterPullURLMismatch)
		log.Info("ANSP direct notification; the dataset is read from the configured CISP", slog.String("pull_url_host", hostOf(ch.PullUrl)))
	case rc.cfg.PullURL == nil:
		rc.cfg.Counters.Inc(CounterPullURLMismatch)
	default:
		if _, err := rc.cfg.PullURL.CheckPullURL(ch.PullUrl); err != nil {
			rc.cfg.Counters.Inc(CounterPullURLMismatch)
			log.Warn("pull_url not followed; the dataset is read from the configured CISP", slog.String("pull_url_host", hostOf(ch.PullUrl)),
				slog.String("reason", err.Error()))
		} else {
			h.PullURL = ch.PullUrl
		}
	}
	rc.cfg.Trigger(ds, h)
	log.Info("CIS notification accepted; pull started")
	w.WriteHeader(http.StatusNoContent)
}

func (rc *Receiver) unauthorised(w http.ResponseWriter, r *http.Request, err error) {
	rc.cfg.Counters.Inc(CounterBadSignature)
	claim := "token"
	var te *coreauth.TokenError
	if errors.As(err, &te) {
		claim = te.Claim
	}
	rc.refusedLog().Warn("CIS notification refused", slog.String("claim", claim), slog.String("error", short(err.Error())))
	httpx.NewProblem(http.StatusUnauthorized, CounterBadSignature, "", "the notification is not signed by an allowed issuer for this host",
		core.Fieldf(claim, "refused")).Write(w, r)
}

// decodeChange reads a cis/change/v1 record. Members the receiver does
// not know are ignored and its reason is an open enumeration (records
// are additive within v1); the members it needs are checked.
func decodeChange(body json.RawMessage) (cispclient.Change, Dataset, *core.FieldError) {
	var c cispclient.Change
	if err := json.Unmarshal(body, &c); err != nil {
		return c, "", core.Fieldf("body", "not a %s record", ChangeSchema)
	}
	if string(c.Schema) != ChangeSchema {
		return c, "", core.Fieldf("schema", "must be %s", ChangeSchema)
	}
	ds, ok := ParseDataset(string(c.Dataset))
	if !ok {
		return c, "", core.Fieldf("dataset", "not a CIS dataset")
	}
	if c.Version < 0 {
		return c, "", core.Fieldf("version", "negative")
	}
	if c.Reason == "" {
		return c, "", core.Fieldf("reason", "empty")
	}
	return c, ds, nil
}

// hostOf is the host of an absolute URL, or "".
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return ""
	}
	return u.Hostname()
}

func idString(id int64) string { return strconv.FormatInt(id, 10) }
