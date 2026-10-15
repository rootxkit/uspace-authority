package dpviews

// The Display Provider's own status (dp/status/v1, schemas/dp/status/v1.json):
// dp-poller publishes it on core NATS subject StatusSubject every status
// interval, whatever Service Providers it holds, so picture-ws can tell a
// Display Provider that works and has nothing to poll (no ISA in any
// viewed area, spec 02 F3411 row: "views exist only where ISAs exist")
// from one that is down, unconfigured or cut off from the DSS. The
// per-provider rows stay on src.v1.network_rid.<uss_id>.
const (
	StatusSubject = "dp.v1.status"
	StatusSchema  = "dp/status/v1"
)

// DSS states of Status.DSS: answered (the last ISA search succeeded),
// unavailable (it failed), unconfigured (no DSS_BASE_URL), or unknown
// (no search yet: nothing viewed, or just started).
const (
	DSSAnswered     = "ok"
	DSSUnavailable  = "dss_unavailable"
	DSSUnconfigured = "dss_unconfigured"
	DSSUnknown      = "unknown"
)

// Status is dp/status/v1's body.
type Status struct {
	DSS       string  `json:"dss"`
	DSSSince  *string `json:"dss_since"`
	Tiles     int     `json:"tiles"`
	ISAs      int     `json:"isas"`
	Providers int     `json:"providers"`
	// UnpolledISAs are ISAs in view whose Service Provider cannot be
	// polled (bad owner, refused or clashing base URL, provider bound):
	// their flights are missing.
	UnpolledISAs int `json:"unpolled_isas"`
}
