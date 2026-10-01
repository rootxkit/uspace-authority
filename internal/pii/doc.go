// Package pii seals personal and secret column values at the
// application layer (docs/PLAN.md D9): AES-256-GCM from the standard
// library with a key read from a file named by configuration
// (PII_KEY_FILE) and a key id stored beside each value, so a later key
// can be added without rewriting every row. The associated data binds a
// sealed value to its row (for example "user_mfa:<user id>"), so a value
// copied into another row does not open. WP-2 seals TOTP secrets with
// it; WP-3 the registry's PII columns.
package pii
