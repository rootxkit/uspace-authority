package receivers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/logging"
)

// E-01: a valid heartbeat parses; an invalid position, altitude,
// firmware or queue depth is named.
func TestParseHeartbeat(t *testing.T) {
	ok := `{"receiver_id":"rx-1","sent_at_ms":1,"nonce":"n","position":{"lat_deg":41.7,"lon_deg":44.8,"alt_hae_m":500},"firmware":"1.0","queue_depth":3,"extra":true}`
	hb, err := parseHeartbeat([]byte(ok))
	if err != nil || hb.Position == nil || *hb.Firmware != "1.0" {
		t.Fatalf("valid: %+v %v", hb, err)
	}
	for name, raw := range map[string]string{
		"not json": `{`,
		"position": `{"position":{"lat_deg":91,"lon_deg":0}}`,
		"altitude": `{"position":{"lat_deg":1,"lon_deg":0,"alt_hae_m":20000}}`,
		"firmware": `{"firmware":"` + strings.Repeat("f", 101) + `"}`,
		"depth":    `{"queue_depth":-1}`,
		"oversize": `{"firmware":"` + strings.Repeat("f", MaxHeartbeatBytes) + `"}`,
	} {
		if _, err := parseHeartbeat([]byte(raw)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseHeartbeat(f *testing.F) {
	f.Add([]byte(`{"receiver_id":"rx-1","sent_at_ms":1,"nonce":"n","position":{"lat_deg":41.7,"lon_deg":44.8}}`))
	f.Add([]byte(`{"position":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		hb, err := parseHeartbeat(raw)
		if err == nil && hb.Position != nil && !validPosition(hb.Position.LatDeg, hb.Position.LonDeg) {
			t.Fatalf("accepted an invalid position %+v", hb.Position)
		}
	})
}

// The heartbeat's size is bounded before anything is read or hashed: a
// declared length above it is refused with 413 and counted.
func TestHeartbeatOversizeIsRefusedFirst(t *testing.T) {
	a := &ReceiverAPI{Counters: &core.Counters{}, Limiter: logging.NewLimiter(logging.Discard(), time.Minute, 0, nil)}
	mux := http.NewServeMux()
	a.Mount(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/rid/receivers/rx-1/heartbeat", strings.NewReader(strings.Repeat("x", MaxHeartbeatBytes+1)))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || a.Counters.Get(ReasonOversize) != 1 {
		t.Fatalf("%d %v", rec.Code, a.Counters.Snapshot())
	}
	// Without a declared length the read stops one byte past the bound.
	req = httptest.NewRequest(http.MethodPost, "/v1/rid/receivers/rx-1/heartbeat", strings.NewReader(strings.Repeat("x", MaxHeartbeatBytes+1)))
	req.ContentLength = -1
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || a.Counters.Get(ReasonOversize) != 2 {
		t.Fatalf("chunked: %d", rec.Code)
	}
}
