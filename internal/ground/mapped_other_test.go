//go:build !(linux || darwin)

package ground

import "testing"

// Where core cannot map a file it reads it into memory, and the process
// says so (geoid_mapped and terrain_mapped false) with the same answers.
// The twin for linux and darwin is mapped_unix_test.go.
func TestNewLoadsThroughTheFallbackRead(t *testing.T) {
	checkLoadPath(t, false)
}
