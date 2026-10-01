// Package config loads one struct per process from the environment.
// Every URL, hostname, key path and threshold of a process comes from
// here. The struct tags (env, default, required, secret, enum, kind,
// min, max, help) are read by hand, without a library; Load reports
// every problem as a *core.FieldError naming the variable, and String
// redacts secrets so a configuration can be logged at start.
package config
