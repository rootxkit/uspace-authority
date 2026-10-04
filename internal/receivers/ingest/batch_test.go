package ingest

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/receivers"
)

// E-01: a valid batch parses with every member; each fault is refused by
// its JSON path.
func TestParseBatchAcceptsAValidBatchAndNamesEachFault(t *testing.T) {
	ok := batchBody("rx-1", 1, "n-1", true, obs(tx1, payload(1, 1), "2026-10-02T09:15:05.120Z"), obs("AA:BB:CC:00:00:02", "0f", ""))
	b, err := ParseBatch([]byte(ok))
	if err != nil {
		t.Fatalf("valid: %v", err)
	}
	if !b.Backlog || len(b.Observations) != 2 || b.Observations[0].RxTS == nil || b.Observations[1].RxTS != nil ||
		b.Observations[0].ReceiverPosition == nil || len(b.Observations[1].Payload) != 1 {
		t.Fatalf("%+v", b)
	}
	cases := map[string][2]string{
		"not json":            {`{`, "body"},
		"bad receiver":        {`{"receiver_id":"RX 1","nonce":"n","observations":[]}`, "receiver_id"},
		"nonce control":       {`{"receiver_id":"rx-1","nonce":"a\u0000b","observations":[]}`, "nonce"},
		"no observations":     {`{"receiver_id":"rx-1","nonce":"n"}`, "observations"},
		"too many":            {batchBody("rx-1", 1, "n", false, strings.TrimSuffix(strings.Repeat(obs(tx1, "00", "")+",", 65), ",")), "observations"},
		"observation type":    {batchBody("rx-1", 1, "n", false, `[]`), "observations[0]"},
		"no transmitter":      {batchBody("rx-1", 1, "n", false, `{"payload_hex":"00"}`), "observations[0].transmitter"},
		"bad transmitter":     {batchBody("rx-1", 1, "n", false, obs("AA-BB", "00", "")), "observations[0].transmitter"},
		"no payload":          {batchBody("rx-1", 1, "n", false, `{"transmitter":"AA:BB:CC:00:00:01"}`), "observations[0].payload_hex"},
		"odd payload":         {batchBody("rx-1", 1, "n", false, obs(tx1, "abc", "")), "observations[0].payload_hex"},
		"not hex":             {batchBody("rx-1", 1, "n", false, obs(tx1, "zz", "")), "observations[0].payload_hex"},
		"payload too long":    {batchBody("rx-1", 1, "n", false, obs(tx1, strings.Repeat("00", receivers.MaxPayloadBytes+1), "")), "observations[0].payload_hex"},
		"rssi":                {batchBody("rx-1", 1, "n", false, `{"transmitter":"AA:BB:CC:00:00:01","payload_hex":"00","rssi_dbm":99}`), "observations[0].rssi_dbm"},
		"rx_ts not utc":       {batchBody("rx-1", 1, "n", false, obs(tx1, "00", "2026-10-02T09:15:05+04:00")), "observations[0].rx_ts"},
		"rx_ts garbage":       {batchBody("rx-1", 1, "n", false, obs(tx1, "00", "yesterdayZ")), "observations[0].rx_ts"},
		"position":            {batchBody("rx-1", 1, "n", false, `{"transmitter":"AA:BB:CC:00:00:01","payload_hex":"00","receiver_position":{"lat_deg":95,"lon_deg":0}}`), "observations[0].receiver_position"},
		"position altitude":   {batchBody("rx-1", 1, "n", false, `{"transmitter":"AA:BB:CC:00:00:01","payload_hex":"00","receiver_position":{"lat_deg":1,"lon_deg":0,"alt_hae_m":99999}}`), "observations[0].receiver_position.alt_hae_m"},
		"number out of range": {`{"receiver_id":"rx-1","sent_at_ms":1e400,"nonce":"n","observations":[]}`, "body"},
	}
	for name, c := range cases {
		_, err := ParseBatch([]byte(c[0]))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		fes := fieldErrors(err)
		if len(fes) == 0 || fes[0].Field != c[1] {
			t.Errorf("%s: %v, want field %s", name, err, c[1])
		}
	}
	if _, err := ParseBatch(make([]byte, receivers.MaxBatchBytes+1)); err == nil {
		t.Error("oversize accepted")
	}
}

// A hostile batch with thousands of faults reports at most 100.
func TestParseBatchBoundsItsErrors(t *testing.T) {
	var o []string
	for range 64 {
		o = append(o, `{"transmitter":"x","payload_hex":"x","rssi_dbm":999,"rx_ts":"x"}`)
	}
	_, err := ParseBatch([]byte(batchBody("rx-1", 1, "n", false, o...)))
	if n := len(fieldErrors(err)); n != maxFieldErrors {
		t.Fatalf("%d errors", n)
	}
}

// Every decoder entry is fuzzed: ParseBatch never panics, and what it
// accepts is within the schema's bounds.
func FuzzParseBatch(f *testing.F) {
	f.Add([]byte(batchBody("rx-1", 1, "n-1", true, obs(tx1, payload(1, 1), "2026-10-02T09:15:05.120Z"))))
	f.Add([]byte(`{"receiver_id":"rx-1","nonce":"n","observations":[{}]}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{"observations":null}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := ParseBatch(raw)
		if err != nil {
			return
		}
		if len(b.Observations) > receivers.MaxObservations || !receivers.ValidID(b.ReceiverID) || !validNonce(b.Nonce) {
			t.Fatalf("accepted out of bounds: %+v", b)
		}
		for _, o := range b.Observations {
			if len(o.Payload) == 0 || len(o.Payload) > receivers.MaxPayloadBytes || !transmitterPattern.MatchString(o.Transmitter) {
				t.Fatalf("observation out of bounds: %+v", o)
			}
		}
		_ = Rows(&b, time.Unix(0, 0))
	})
}

// The frame id is the dedupe key's hash: equal for the same observation
// heard twice, different for another receiver, transmitter, time or
// payload; without rx_ts it includes the batch nonce and position.
func TestFrameID(t *testing.T) {
	at := time.Date(2026, 10, 2, 9, 15, 5, 120e6, time.UTC)
	sum := sha256.Sum256([]byte{1})
	base, ok := FrameID("rx-1", tx1, &at, sum, "n-1", 0)
	if !ok || len(base) != 32 {
		t.Fatalf("%s %v", base, ok)
	}
	if again, _ := FrameID("rx-1", tx1, &at, sum, "n-2", 5); again != base {
		t.Fatal("the nonce changed a dedupable frame's id")
	}
	later := at.Add(time.Millisecond)
	for name, id := range map[string]string{
		"receiver":    must(FrameID("rx-2", tx1, &at, sum, "n-1", 0)),
		"transmitter": must(FrameID("rx-1", "AA:BB:CC:00:00:02", &at, sum, "n-1", 0)),
		"time":        must(FrameID("rx-1", tx1, &later, sum, "n-1", 0)),
		"payload":     must(FrameID("rx-1", tx1, &at, sha256.Sum256([]byte{2}), "n-1", 0)),
	} {
		if id == base {
			t.Errorf("%s did not change the id", name)
		}
	}
	a, dedupable := FrameID("rx-1", tx1, nil, sum, "n-1", 0)
	b, _ := FrameID("rx-1", tx1, nil, sum, "n-1", 1)
	if dedupable || a == b {
		t.Fatal("frames without rx_ts must never share an id")
	}
}

func must(id string, _ bool) string { return id }

func TestBatchIDNeverCarriesTheNonce(t *testing.T) {
	id := BatchID("rx-1", "evil\r\nNats-Msg-Id: x")
	if strings.ContainsAny(id, "\r\n ") || !strings.HasPrefix(id, "rx-1:") || len(id) != len("rx-1:")+16 {
		t.Fatalf("%q", id)
	}
	if a, b, a2 := BatchID("rx-1", "a"), BatchID("rx-1", "b"), BatchID("rx-1", "a"); a == b || a != a2 {
		t.Fatal("not a function of the nonce")
	}
}

func TestRowsLeaveMsgTypeEmptyForNoPayloadAndCopyThePosition(t *testing.T) {
	b := Batch{ReceiverID: "rx-1", Nonce: "n", Observations: []Observation{{Transmitter: tx1, Payload: []byte{0x42}}}}
	rows := Rows(&b, time.Unix(1, 0))
	if *rows[0].MsgType != 4 || rows[0].ReceiverLatDeg != nil {
		t.Fatalf("%+v", rows[0])
	}
	b.Observations[0].Payload = nil
	if rows := Rows(&b, time.Unix(1, 0)); rows[0].MsgType != nil {
		t.Fatal("a type for an empty payload")
	}
}
