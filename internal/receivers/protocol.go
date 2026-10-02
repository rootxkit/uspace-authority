package receivers

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// The receiver protocol's fixed bounds (spec 02 F9, 06 §2 T2,
// rid/observation/v1). They are the contract every receiver is built
// against, published by GET .../config, not tunable policy.
const (
	// MaxBatchBytes bounds an observation batch body; the body is cut
	// there before anything parses it.
	MaxBatchBytes = 64 << 10
	// MaxObservations bounds the observations of one batch.
	MaxObservations = 64
	// MaxPayloadBytes bounds one decoded payload: an ODID message is 25
	// bytes and a message pack at most 3 + 9 x 25 = 228 (uspace-core
	// odid refuses anything malformed in it later, WP-8).
	MaxPayloadBytes = 512
	// MaxHeartbeatBytes bounds a heartbeat body.
	MaxHeartbeatBytes = 4 << 10
	// MaxSkew is the sent_at_ms window (R-06, rid_receiver_auth.json);
	// a nonce is remembered for twice it.
	MaxSkew = 30 * time.Second
	// signatureSuffixBytes is "\nsig=" and 64 hex characters.
	signatureSuffixBytes = len(auth.SignatureMarker) + 64
)

// MaxDatagramBytes is what core may be handed for a body of maxBody bytes.
func MaxDatagramBytes(maxBody int) int { return maxBody + signatureSuffixBytes }

// Problem slugs of the receiver endpoints (docs/runbooks/receivers.md).
const (
	SlugUnauthenticated  = httpx.SlugUnauthn
	SlugSignature        = "signature"
	SlugSkew             = "skew"
	SlugReplay           = "replay"
	SlugValidation       = httpx.SlugValidation
	SlugSourceDisabled   = "source_disabled"
	SlugQueueFull        = "queue_full"
	SlugQueueUnavailable = "queue_unavailable"
	SlugBusy             = "busy"
)

// Refusal is one refused receiver request: its status, problem slug and
// the counter it increments (E-09).
type Refusal struct {
	Status  int
	Slug    string
	Counter string
	Detail  string
	// RetryAfter is set on a 503 (B-10): the receiver retries, never
	// gives up.
	RetryAfter time.Duration
}

// Refusal reasons (counter names of the ingest and of api's receiver
// endpoints); the core verifier's own counters keep its phrases.
const (
	ReasonUnauthenticated  = "refused_unauthenticated"
	ReasonUnsigned         = "refused_unsigned"
	ReasonUnknownReceiver  = "refused_unknown_receiver"
	ReasonBadSignature     = "refused_bad_signature"
	ReasonSkew             = "refused_skew"
	ReasonReplay           = "refused_replay"
	ReasonMalformed        = "refused_malformed"
	ReasonOversize         = "refused_oversize"
	ReasonDisabled         = "refused_disabled"
	ReasonQueueFull        = "refused_queue_full"
	ReasonQueueUnavailable = "refused_queue_unavailable"
	ReasonBusy             = "refused_busy"
)

// VerifyRefusal maps a refusal of uspace-core's ReceiverVerifier onto the
// HTTP answer: unsigned, unknown receiver and a bad signature are 401
// `signature`; a sent_at_ms outside the window is 401 `skew`; a repeated
// nonce is 409 `replay`; a malformed report is 400. Never 403 (B-10).
func VerifyRefusal(err error) Refusal {
	var re *auth.ReceiverError
	if !errors.As(err, &re) {
		return Refusal{Status: http.StatusBadRequest, Slug: SlugValidation, Counter: ReasonMalformed, Detail: "not a receiver report"}
	}
	switch re.Counter {
	case auth.CounterRejectedUnsigned:
		return Refusal{Status: http.StatusUnauthorized, Slug: SlugSignature, Counter: ReasonUnsigned, Detail: re.Reason}
	case auth.CounterRejectedUnknownReceiver:
		return Refusal{Status: http.StatusUnauthorized, Slug: SlugSignature, Counter: ReasonUnknownReceiver, Detail: re.Reason}
	case auth.CounterRejectedBadSignature:
		return Refusal{Status: http.StatusUnauthorized, Slug: SlugSignature, Counter: ReasonBadSignature, Detail: re.Reason}
	case auth.CounterRejectedSkew:
		return Refusal{Status: http.StatusUnauthorized, Slug: SlugSkew, Counter: ReasonSkew, Detail: re.Reason}
	case auth.CounterRejectedReplay:
		return Refusal{Status: http.StatusConflict, Slug: SlugReplay, Counter: ReasonReplay, Detail: re.Reason}
	}
	return Refusal{Status: http.StatusBadRequest, Slug: SlugValidation, Counter: ReasonMalformed, Detail: re.Reason}
}

// AuthRefusal maps a Keyring.Authenticate error.
func AuthRefusal(err error) Refusal {
	if errors.Is(err, ErrBusy) {
		return Refusal{Status: http.StatusServiceUnavailable, Slug: SlugBusy, Counter: ReasonBusy,
			Detail: "the key check is saturated; retry", RetryAfter: time.Second}
	}
	return Refusal{Status: http.StatusUnauthorized, Slug: SlugUnauthenticated, Counter: ReasonUnauthenticated,
		Detail: "no or unknown receiver key"}
}

// Write sends the refusal as a problem, with Retry-After when set.
func (f Refusal) Write(w http.ResponseWriter, r *http.Request, errs ...*core.FieldError) {
	if f.RetryAfter > 0 {
		s := int(f.RetryAfter / time.Second)
		if s < 1 {
			s = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(s))
	}
	if f.Status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="rid-receivers"`)
	}
	httpx.NewProblem(f.Status, f.Slug, "", f.Detail, errs...).Write(w, r)
}
