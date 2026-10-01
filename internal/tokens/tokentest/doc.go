// Package tokentest makes RSA keys for tests at run time (spec 06 §4:
// no key, not even a test key, is ever in the repository). Keys are
// generated once per test binary and shared; files are written into the
// test's temporary directory. Imported by _test.go files only.
package tokentest
