package cisp_test

import (
	"os"
	"testing"
)

// TestIntegrationPlantedFailure is planted to prove that a failing test fails the job.
func TestIntegrationPlantedFailure(t *testing.T) {
	if os.Getenv("INTEGRATION") == "" {
		t.Skip("INTEGRATION not set")
	}
	t.Fatal("planted failure: this test must fail the job")
}
