// Package passhash hashes and verifies secrets that a person or a client
// presents: console passwords (internal/authz) and OAuth client secrets
// (internal/tokens). It is argon2id from golang.org/x/crypto/argon2 in
// the PHC string format, compared in constant time. Nothing here is a
// hand-written primitive: the package chooses parameters, encodes and
// compares.
//
// Parameters: the defaults are the OWASP Password Storage Cheat Sheet's
// argon2id recommendation current at the time of writing (2026-10):
// "a minimum configuration of 19 MiB of memory, an iteration count of 2,
// and 1 degree of parallelism" (m=19456 KiB, t=2, p=1), with a 16-byte
// salt and a 32-byte tag. They come from configuration
// (ARGON2_MEMORY_KIB, ARGON2_TIME, ARGON2_THREADS, internal/config),
// whose lower bounds are that minimum. A stored hash carries its own
// parameters, so raising them never locks anyone out; NeedsRehash says
// when a stored hash is weaker than the current parameters.
package passhash
