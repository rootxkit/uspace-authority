// Package corevectors pins the uspace-core packages whose own vector
// tests `make vectors` runs from the module cache, so that their whole
// dependency graph (including jwx, which this repository reaches only
// through core/auth) is in go.sum. It has no code of its own.
package corevectors
