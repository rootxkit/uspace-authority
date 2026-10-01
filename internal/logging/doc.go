// Package logging is the slog JSON setup of every process, the
// rate-limited logger (the first event of a key, then at most one per
// interval with the suppressed count, over a bounded key set; E-09,
// E-10) and the periodic status line carrying every core.Counters
// snapshot, so that silence is distinguishable from health.
package logging
