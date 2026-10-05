package picture

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/cell"
	"github.com/rootxkit/uspace-authority/internal/httpx"
)

// The routes of picture-ws (api/openapi.yaml, x-picture).
const (
	PatternWS       = "GET /v1/picture/ws"
	PatternSnapshot = "GET /v1/picture/snapshot"
	PatternSources  = "GET /v1/picture/sources"
)

// Problem slugs of picture-ws's refusals.
const (
	SlugUpgradeRequired = "upgrade_required"
	SlugOrigin          = "origin"
	SlugPictureFull     = "picture_full"
	SlugSessionCheck    = "session_unavailable"
)

// Handler serves the three routes of the picture.
type Handler struct {
	Hub      *Hub
	Sessions Checker
	// Origins are the allowed origins, normalised (config.OriginOf);
	// the Origin header must equal one exactly (M22).
	Origins []string
	// SessionTimeout bounds the session check of an upgrade or a read.
	SessionTimeout time.Duration
	// SourcesState is the body of GET /v1/picture/sources beyond the
	// sources (the projections and the bus); nil answers without them.
	SourcesState func(now time.Time) SourcesExtras
}

// Mount registers the routes on mux.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc(PatternWS, h.serveWS)
	mux.HandleFunc(PatternSnapshot, h.serveSnapshot)
	mux.HandleFunc(PatternSources, h.serveSources)
}

func isUpgrade(r *http.Request) bool {
	return headerHas(r.Header, "Connection", "upgrade") && headerHas(r.Header, "Upgrade", "websocket")
}

func headerHas(hd http.Header, name, token string) bool {
	for _, v := range hd.Values(name) {
		for part := range strings.SplitSeq(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// originAllowed reports whether origin is exactly one of the allowed
// origins (scheme, host and port; no wildcard, M22).
func (h *Handler) originAllowed(origin string) bool {
	return origin != "" && slices.Contains(h.Origins, origin)
}

func (h *Handler) sessionCtx(r *http.Request) (context.Context, context.CancelFunc) {
	d := h.SessionTimeout
	if d <= 0 {
		d = 3 * time.Second
	}
	return context.WithTimeout(r.Context(), d)
}

// serveWS is GET /v1/picture/ws. Before the upgrade: a request without
// a uspace_session cookie is 401 (it is unauthenticated, whatever else
// it lacks; conformance C4), a request that is not a WebSocket upgrade
// is 426, an Origin outside the allow-list (or none: only a browser on
// an allowed origin is a console) is 403 and never upgraded, a full
// instance is 503 with Retry-After. After it: a token that is not a
// live console session (machine tokens included) closes with 4401
// (re-login); a check that cannot be made closes with 1013. Nothing is
// read from the query string: there is no ticket (M22).
func (h *Handler) serveWS(w http.ResponseWriter, r *http.Request) {
	hub := h.Hub
	var token string
	if c, err := r.Cookie(CookieSession); err == nil {
		token = c.Value
	}
	if token == "" {
		hub.counters.Inc(CounterRefusedNoSession)
		httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "",
			"no "+CookieSession+" cookie on the upgrade: sign in through /v1/auth/login").Write(w, r)
		return
	}
	if !isUpgrade(r) {
		hub.counters.Inc(CounterRefusedRequest)
		w.Header().Set("Upgrade", "websocket")
		httpx.NewProblem(http.StatusUpgradeRequired, SlugUpgradeRequired, "WebSocket upgrade required",
			"this operation is a WebSocket upgrade (Connection: Upgrade, Upgrade: websocket)").Write(w, r)
		return
	}
	if origin := r.Header.Get("Origin"); !h.originAllowed(origin) {
		hub.counters.Inc(CounterRefusedOrigin)
		hub.cfg.Limiter.Limited("picture_origin_refused").Warn("picture upgrade refused: Origin not allowed",
			slog.String("origin", truncate(origin, 128)))
		httpx.NewProblem(http.StatusForbidden, SlugOrigin, "Origin not allowed",
			"the console connects same-origin; this Origin is not on PICTURE_ALLOWED_ORIGINS",
			&core.FieldError{Field: "Origin", Reason: "not an allowed origin"}).Write(w, r)
		return
	}
	if !hub.Reserve() {
		hub.counters.Inc(CounterRefusedCapacity)
		w.Header().Set("Retry-After", strconv.Itoa(max(1, int(hub.cfg.StatusInterval/time.Second))))
		httpx.NewProblem(http.StatusServiceUnavailable, SlugPictureFull, "Picture full",
			"this instance serves its maximum of consoles (PICTURE_MAX_CLIENTS)").Write(w, r)
		return
	}
	ctx, cancel := h.sessionCtx(r)
	sess, serr := h.Sessions.Check(ctx, token)
	cancel()
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // the Origin was judged above, exactly
		CompressionMode:    websocket.CompressionDisabled,
	})
	if err != nil {
		hub.Release()
		return // Accept has answered
	}
	conn.SetReadLimit(hub.cfg.SubscribeMaxBytes)
	if serr != nil {
		hub.Release()
		code, reason := CloseRelogin, "sign in again"
		if errors.Is(serr, ErrRefused) {
			hub.counters.Inc(CounterClosedRelogin)
		} else {
			code, reason = CloseTryAgainLater, "the session could not be checked; reconnect later"
			hub.counters.Inc(CounterClosedUnavailable)
		}
		hub.cfg.Limiter.Limited("picture_session_refused").Info("picture console refused", slog.String("error", serr.Error()),
			slog.Int("close_code", int(code)))
		go func() { _ = conn.Close(code, reason) }()
		return
	}
	hub.Serve(WSConn{C: conn}, sess, token, h.Sessions)
}

// identify is the session of a plain GET: the bearer the BFF forwards,
// or the uspace_session cookie of a same-origin read (an Origin, when
// sent, must be allowed). The answer is written when it fails.
func (h *Handler) identify(w http.ResponseWriter, r *http.Request) (Session, bool) {
	if origin := r.Header.Get("Origin"); origin != "" && !h.originAllowed(origin) {
		h.Hub.counters.Inc(CounterRefusedOrigin)
		httpx.NewProblem(http.StatusForbidden, SlugOrigin, "Origin not allowed", "this Origin is not on PICTURE_ALLOWED_ORIGINS",
			&core.FieldError{Field: "Origin", Reason: "not an allowed origin"}).Write(w, r)
		return Session{}, false
	}
	var token string
	switch vals := r.Header.Values("Authorization"); {
	case len(vals) > 1:
		httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "", "more than one Authorization header").Write(w, r)
		return Session{}, false
	case len(vals) == 1:
		scheme, t, ok := strings.Cut(vals[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "", "the Authorization header is not a bearer token").Write(w, r)
			return Session{}, false
		}
		token = strings.TrimSpace(t)
	default:
		if c, err := r.Cookie(CookieSession); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "", "no session: sign in through /v1/auth/login").Write(w, r)
		return Session{}, false
	}
	ctx, cancel := h.sessionCtx(r)
	defer cancel()
	sess, err := h.Sessions.Check(ctx, token)
	switch {
	case err == nil:
		return sess, true
	case errors.Is(err, ErrRefused):
		httpx.NewProblem(http.StatusUnauthorized, httpx.SlugUnauthn, "", err.Error()).Write(w, r)
	default:
		w.Header().Set("Retry-After", "5")
		httpx.NewProblem(http.StatusServiceUnavailable, SlugSessionCheck, "Session check unavailable", err.Error()).Write(w, r)
	}
	return Session{}, false
}

// serveSnapshot is GET /v1/picture/snapshot?bbox=w,s,e,n[&layers=...]:
// the console/snapshot/v1 frame a WebSocket console receives, with the
// tracks inside the box itself (no margin), for every layer unless
// layers names some.
func (h *Handler) serveSnapshot(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.identify(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	raw := q.Get("bbox")
	if raw == "" || len(q["bbox"]) > 1 {
		httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", "bbox is required, once",
			&core.FieldError{Field: "bbox", Reason: "required: west,south,east,north"}).Write(w, r)
		return
	}
	parts := strings.Split(raw, ",")
	nums := make([]float64, 0, len(parts))
	for _, p := range parts {
		x, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil {
			httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", "bbox is four numbers",
				&core.FieldError{Field: "bbox", Reason: "four numbers west,south,east,north"}).Write(w, r)
			return
		}
		nums = append(nums, x)
	}
	box, err := ParseBBox(nums, "bbox")
	var cells map[cell.ID]struct{}
	if err == nil {
		cells, err = ViewportCells(box, h.Hub.cfg.MaxCells)
	}
	if err != nil {
		var fe *core.FieldError
		errors.As(err, &fe)
		httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", err.Error(), fe).Write(w, r)
		return
	}
	layers := map[string]bool{LayerTracks: true, LayerManned: true, LayerAlerts: true, LayerZones: true}
	if lv := q.Get("layers"); lv != "" {
		layers = map[string]bool{}
		for l := range strings.SplitSeq(lv, ",") {
			switch l {
			case LayerTracks, LayerManned, LayerAlerts, LayerZones:
				layers[l] = true
			default:
				httpx.NewProblem(http.StatusBadRequest, httpx.SlugValidation, "Invalid request", "unknown layer",
					core.Fieldf("layers", "%q is not tracks, manned, alerts or zones", truncate(l, 32))).Write(w, r)
				return
			}
		}
	}
	now := h.Hub.cfg.Now()
	body := h.Hub.snapshotBody(snapshotFilter{cells: cells, layers: layers, console: sess.Console(), box: &box}, now)
	f, err := systemFrame(SchemaSnapshot, now, body)
	if err != nil {
		httpx.NewProblem(http.StatusInternalServerError, httpx.SlugInternal, "", "the snapshot could not be encoded").Write(w, r)
		return
	}
	writeJSON(w, f)
}

// SourcesExtras are the members of GET /v1/picture/sources beside the
// sources.
type SourcesExtras struct {
	RegistryAgeS *float64 `json:"projection_age_s"`
	ZonesVersion *string  `json:"zones_version"`
	CISVersion   *string  `json:"cis_version"`
	CISAgeS      *float64 `json:"cis_age_s"`
	NATS         string   `json:"nats"`
	NATSSince    *string  `json:"nats_since"`
}

// sourcesBody is GET /v1/picture/sources.
type sourcesBody struct {
	ServerTS string        `json:"server_ts"`
	Sources  []SourceState `json:"sources"`
	SourcesExtras
}

// serveSources is GET /v1/picture/sources: every source with its state
// (the last src.v1 status and the switches), the projection ages and
// the CIS age.
func (h *Handler) serveSources(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.identify(w, r); !ok {
		return
	}
	now := h.Hub.cfg.Now()
	b := sourcesBody{ServerTS: stamp(now), Sources: h.Hub.sources.Snapshot()}
	if b.Sources == nil {
		b.Sources = []SourceState{}
	}
	if h.SourcesState != nil {
		b.SourcesExtras = h.SourcesState(now)
	} else {
		b.NATS = NATSConnected
	}
	raw, err := json.Marshal(b)
	if err != nil {
		httpx.NewProblem(http.StatusInternalServerError, httpx.SlugInternal, "", "the sources could not be encoded").Write(w, r)
		return
	}
	writeJSON(w, raw)
}

func writeJSON(w http.ResponseWriter, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// WSConn adapts *websocket.Conn to Conn: every frame is a text message;
// a binary message from the console is refused like an invalid frame.
type WSConn struct{ C *websocket.Conn }

// Read reads one text message.
func (c WSConn) Read(ctx context.Context) ([]byte, error) {
	typ, b, err := c.C.Read(ctx)
	if err != nil {
		return nil, err
	}
	if typ != websocket.MessageText {
		return []byte("binary"), nil
	}
	return b, nil
}

// Write sends frame as one text message.
func (c WSConn) Write(ctx context.Context, frame []byte) error {
	return c.C.Write(ctx, websocket.MessageText, frame)
}

// Close closes the connection with code and reason.
func (c WSConn) Close(code websocket.StatusCode, reason string) error { return c.C.Close(code, reason) }
