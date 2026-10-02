// Package bustest gives integration tests the NATS JetStream of the
// development stack (NATS_URL). It runs only with INTEGRATION=1 and
// otherwise skips, saying why. It is imported by _test.go files only.
//
// Tests that delete or recreate the shared streams (INGEST, TSW, the
// topology of bus.Ensure) assume no other package's tests run against
// the same server at the same time: `make integration` and CI run the
// packages one at a time (go test -p 1).
package bustest

import (
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// URL is NATS_URL, or a skip when INTEGRATION=1 is not set.
func URL(t testing.TB) string {
	t.Helper()
	if os.Getenv("INTEGRATION") != "1" {
		t.Skip("INTEGRATION=1 not set: needs NATS JetStream (make up)")
	}
	u := os.Getenv("NATS_URL")
	if u == "" {
		t.Fatal("INTEGRATION=1 but NATS_URL is unset")
	}
	return u
}

// Connect connects to URL and closes the connection when the test ends.
func Connect(t testing.TB) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	nc, err := nats.Connect(URL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return nc, js
}

var seq atomic.Int64

// Name is a bucket or subject token unique to this test run, so tests
// sharing one server never read each other's state.
func Name(prefix string) string {
	return fmt.Sprintf("%s_%d_%d", prefix, time.Now().UnixNano(), seq.Add(1))
}
