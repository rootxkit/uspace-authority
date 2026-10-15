package picture

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/rootxkit/uspace-authority/internal/dpviews"
)

// CounterDPStatusMalformed counts dp.v1.status messages refused.
const CounterDPStatusMalformed = "dp_status_malformed"

// dpSelf holds dp-poller's own status (dpviews.Status) and when it came.
type dpSelf struct {
	mu   sync.Mutex
	body dpviews.Status
	at   time.Time
}

// OfferDPStatus takes one dp.v1.status message (dpviews.StatusSchema).
func (h *Hub) OfferDPStatus(raw []byte, now time.Time) {
	if len(raw) > maxMessageBytes {
		h.counters.Inc(CounterDPStatusMalformed)
		h.cfg.Limiter.Limited("picture_dp_status_malformed").Warn("Display Provider status refused", slog.Int("bytes", len(raw)))
		return
	}
	var env struct {
		Schema string         `json:"schema"`
		Body   dpviews.Status `json:"body"`
	}
	if err := json.Unmarshal(raw, &env); err != nil || env.Schema != dpviews.StatusSchema || env.Body.DSS == "" {
		h.counters.Inc(CounterDPStatusMalformed)
		h.cfg.Limiter.Limited("picture_dp_status_malformed").Warn("Display Provider status refused", slog.String("schema", env.Schema))
		return
	}
	h.dp.mu.Lock()
	h.dp.body, h.dp.at = env.Body, now
	h.dp.mu.Unlock()
}

// dpFresh is dp-poller's status when it came within fresh of now.
func (h *Hub) dpFresh(now time.Time, fresh time.Duration) (dpviews.Status, bool) {
	h.dp.mu.Lock()
	defer h.dp.mu.Unlock()
	if h.dp.at.IsZero() || fresh <= 0 || now.Sub(h.dp.at) > fresh {
		return dpviews.Status{}, false
	}
	return h.dp.body, true
}

// dpIdle reports whether b says the Display Provider works and has
// nothing to poll: the DSS answered its ISA searches, it holds no ISA in
// view and no Service Provider. That is not unavailable (spec 02 F3411
// row: views exist only where ISAs exist; its failure modes are a USSP
// down or over its response time, shown on that USSP's row, and the DSS
// down, dss_unavailable). An ISA in view that nothing polls is never
// idle: its flight is missing (dp_isas_unpolled).
func dpIdle(b dpviews.Status) bool {
	return b.DSS == dpviews.DSSAnswered && b.ISAs == 0 && b.Providers == 0 && b.UnpolledISAs == 0
}
