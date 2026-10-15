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

// dpIdle reports whether dp-poller said, within fresh of now, that the
// DSS answered its ISA searches and it holds no Service Provider: the
// Display Provider works and nothing in view has an ISA. That is not
// unavailable (spec 02 F3411 row: views exist only where ISAs exist;
// its failure modes are a USSP down or over its response time, shown on
// that USSP's row, and the DSS down, dss_unavailable).
func (h *Hub) dpIdle(now time.Time, fresh time.Duration) bool {
	h.dp.mu.Lock()
	defer h.dp.mu.Unlock()
	if h.dp.at.IsZero() || fresh <= 0 || now.Sub(h.dp.at) > fresh {
		return false
	}
	return h.dp.body.DSS == dpviews.DSSAnswered && h.dp.body.Providers == 0
}
