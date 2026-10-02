package receivers

import (
	"errors"
	"slices"

	"github.com/rootxkit/uspace-core/core"
)

// ReportingFields are the observation members a receiver may report.
var ReportingFields = []string{"transmitter", "payload_hex", "rssi_dbm", "rx_ts", "receiver_position"}

// Config is a receiver's configuration (rid_receivers.config, the
// RIDReceiverConfig schema). A nil member takes the deployment's default
// (Defaults), so no default is stored as a literal (INV-03).
type Config struct {
	BatchIntervalMS    *int     `json:"batch_interval_ms,omitempty"`
	BacklogCap         *int     `json:"backlog_cap,omitempty"`
	HeartbeatIntervalS *int     `json:"heartbeat_interval_s,omitempty"`
	PositionToleranceM *float64 `json:"position_tolerance_m,omitempty"`
	ReportingFields    []string `json:"reporting_fields,omitempty"`
}

// Defaults are the deployment's defaults of every Config member
// (RID_DEFAULT_* variables of api).
type Defaults struct {
	BatchIntervalMS    int
	BacklogCap         int
	HeartbeatIntervalS int
	PositionToleranceM float64
}

// Bounds of the members (the RIDReceiverConfig schema).
const (
	minBatchIntervalMS = 100
	maxBatchIntervalMS = 1000
	maxBacklogCap      = 10_000_000
	maxHeartbeatS      = 300
	maxToleranceM      = 100_000
)

// Validate refuses a member out of its bounds, naming each (E-15: a zero
// or non-finite tolerance refuses the check rather than disarming it).
func (c Config) Validate() error {
	var errs []error
	if v := c.BatchIntervalMS; v != nil && (*v < minBatchIntervalMS || *v > maxBatchIntervalMS) {
		errs = append(errs, core.Fieldf("config.batch_interval_ms", "must be %d to %d", minBatchIntervalMS, maxBatchIntervalMS))
	}
	if v := c.BacklogCap; v != nil && (*v < 1 || *v > maxBacklogCap) {
		errs = append(errs, core.Fieldf("config.backlog_cap", "must be 1 to %d", maxBacklogCap))
	}
	if v := c.HeartbeatIntervalS; v != nil && (*v < 1 || *v > maxHeartbeatS) {
		errs = append(errs, core.Fieldf("config.heartbeat_interval_s", "must be 1 to %d", maxHeartbeatS))
	}
	if v := c.PositionToleranceM; v != nil && (!core.IsFinite(*v) || *v <= 0 || *v > maxToleranceM) {
		errs = append(errs, core.Fieldf("config.position_tolerance_m", "must be finite, above 0 and at most %d", maxToleranceM))
	}
	if len(c.ReportingFields) > len(ReportingFields) {
		errs = append(errs, core.Fieldf("config.reporting_fields", "at most %d fields", len(ReportingFields)))
	}
	seen := map[string]bool{}
	for _, f := range c.ReportingFields {
		if !slices.Contains(ReportingFields, f) {
			errs = append(errs, core.Fieldf("config.reporting_fields", "%q is not a reporting field", f))
		} else if seen[f] {
			errs = append(errs, core.Fieldf("config.reporting_fields", "%q appears twice", f))
		}
		seen[f] = true
	}
	return errors.Join(errs...)
}

// Validate refuses defaults no receiver could be configured with.
func (d Defaults) Validate() error {
	ptr := func(v int) *int { return &v }
	tol := d.PositionToleranceM
	return Config{
		BatchIntervalMS: ptr(d.BatchIntervalMS), BacklogCap: ptr(d.BacklogCap),
		HeartbeatIntervalS: ptr(d.HeartbeatIntervalS), PositionToleranceM: &tol,
	}.Validate()
}

// Resolve fills every nil member from d; the result is what the receiver
// is told (GET .../config).
func (c Config) Resolve(d Defaults) Config {
	out := c
	if out.BatchIntervalMS == nil {
		v := d.BatchIntervalMS
		out.BatchIntervalMS = &v
	}
	if out.BacklogCap == nil {
		v := d.BacklogCap
		out.BacklogCap = &v
	}
	if out.HeartbeatIntervalS == nil {
		v := d.HeartbeatIntervalS
		out.HeartbeatIntervalS = &v
	}
	if out.PositionToleranceM == nil {
		v := d.PositionToleranceM
		out.PositionToleranceM = &v
	}
	if out.ReportingFields == nil {
		out.ReportingFields = slices.Clone(ReportingFields)
	} else {
		out.ReportingFields = slices.Clone(out.ReportingFields)
	}
	return out
}
