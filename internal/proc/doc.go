// Package proc is the shared runtime of the seven processes: it loads
// the configuration (exiting non-zero with the variable named), sets up
// logging, metrics and tracing, serves /healthz, /readyz (through the
// handlers generated from api/openapi.yaml) and /metrics on the admin
// port, emits the periodic status line, runs the process body, and on
// SIGTERM drains within SHUTDOWN_TIMEOUT_S.
package proc
