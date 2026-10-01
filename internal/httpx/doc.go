// Package httpx is the net/http baseline of every listener: header,
// read, write and idle timeouts; a request body cap (1 MiB by default,
// per-route override); request ids; one structured access-log line per
// request; panic recovery; a per-client token-bucket rate limiter over
// a bounded client map; RFC 9457 problem+json errors in the shape of
// the lab's problem/v1; and a Shutdown bounded by a deadline.
package httpx
