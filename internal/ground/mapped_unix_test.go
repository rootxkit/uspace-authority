//go:build linux || darwin

package ground

import "testing"

// On linux and darwin every process maps GEOID_FILE and each tile
// read-only, so the processes on one host share them in the page cache
// (WP-19). The twin for every other platform is mapped_other_test.go.
func TestNewLoadsThroughTheMappedPath(t *testing.T) {
	checkLoadPath(t, true)
}
