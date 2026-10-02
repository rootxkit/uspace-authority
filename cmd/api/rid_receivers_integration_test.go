package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

func natsURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("NATS_URL")
	if u == "" {
		t.Fatal("INTEGRATION=1 but NATS_URL is unset")
	}
	return u
}

// startAPI runs api on a migrated scratch database with env changes and
// returns its base URL and the environment it ran with.
func startAPI(t *testing.T, change func(m map[string]string)) (string, map[string]string, *lines) {
	t.Helper()
	u := storetest.Migrated(t, migrate.Relational)
	identify := func(*http.Request) (apiserver.Identity, error) {
		return apiserver.Identity{ActorType: "user", Subject: "admin-1", Roles: []string{apiserver.RoleAdmin, apiserver.RoleInspector},
			Realm: "console", Session: true}, nil
	}
	m := baseEnv(t, u)
	m["PG_URL_FOR_TEST"] = u
	change(m)
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, specWith(&config.API{}, identify), nil, &stdout, &stderr, env(m)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("exit %d; last lines of stdout:\n%s\nstderr:\n%s", code, stdout.tail(40), stderr.tail(40))
			}
		case <-time.After(20 * time.Second):
			t.Error("api did not stop")
		}
	})
	listen := stdout.waitFor(t, "public listener open", nil)
	return "http://" + listen["addr"].(string), m, &stdout
}

// rxCall sends a receiver request: bearer key, body and its signature.
func rxCall(t *testing.T, method, url, bearer, body string, secret []byte, out any) (int, http.Header) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if secret != nil {
		req.Header.Set(receivers.SignatureHeader, auth.SignReport(secret, []byte(body)))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, resp.Header
}

type creds struct {
	Receiver    map[string]any `json:"receiver"`
	Credentials struct {
		Generation    int    `json:"generation"`
		BearerKey     string `json:"bearer_key"`
		HMACSecretHex string `json:"hmac_secret_hex"`
	} `json:"credentials"`
}

func (c creds) secret(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(c.Credentials.HMACSecretHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func heartbeat(id, nonce string, lat, lon float64) string {
	return fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":%q,"position":{"lat_deg":%v,"lon_deg":%v,"alt_hae_m":530},"firmware":"rx-fw 1.2"}`,
		id, time.Now().UnixMilli(), nonce, lat, lon)
}

// The receiver lifecycle through the real process: create (keys shown
// once), config and a signed heartbeat with the receiver's own keys,
// disable, enable, rotate with a grace and without, delete; the key set
// in KV follows every step, every step is an events row, and the raw
// frames are read with a purpose and audited.
func TestIntegrationReceiverLifecycleThroughTheAPI(t *testing.T) {
	bucket := fmt.Sprintf("rid_keys_api_%d", time.Now().UnixNano())
	base, m, _ := startAPI(t, func(m map[string]string) {
		m["NATS_URL"], m["RID_KEYSET_BUCKET"] = natsURL(t), bucket
	})
	nc, err := nats.Connect(natsURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	js, _ := jetstream.New(nc)
	t.Cleanup(func() { _ = js.DeleteKeyValue(context.Background(), bucket) })
	entry := func(id string) (receivers.Entry, bool) {
		kv, err := js.KeyValue(context.Background(), bucket)
		if err != nil {
			return receivers.Entry{}, false
		}
		e, err := kv.Get(context.Background(), id)
		if err != nil {
			return receivers.Entry{}, false
		}
		out, err := receivers.ParseEntry(id, e.Value())
		if err != nil {
			t.Fatalf("the projected entry does not parse: %v", err)
		}
		return out, true
	}

	// Create: the keys are in the answer, once.
	var c creds
	body := `{"id":"rx-tbs-01","label":"Tbilisi roof","lat_deg":41.7151,"lon_deg":44.8271,"owner":"third_party","owner_name":"TEST Telecom","config":{"position_tolerance_m":50}}`
	code, hdr := rxCall(t, http.MethodPost, base+"/v1/rid/receivers", "", body, nil, &c)
	if code != http.StatusCreated || c.Credentials.Generation != 1 || hdr.Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(c.Credentials.BearerKey, "rx-tbs-01.") || len(c.Credentials.HMACSecretHex) != 64 {
		t.Fatalf("create: %d %+v", code, c)
	}
	var got map[string]any
	code, _ = rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01", "", "", nil, &got)
	raw, _ := json.Marshal(got)
	if code != http.StatusOK || strings.Contains(string(raw), c.Credentials.BearerKey) || strings.Contains(string(raw), c.Credentials.HMACSecretHex) ||
		got["label"] != "Tbilisi roof" || got["key_generation"] != 1.0 {
		t.Fatalf("read back: %d %s", code, raw)
	}
	if e, ok := entry("rx-tbs-01"); !ok || !e.Enabled() || e.Keys[0].HMACSecretHex != c.Credentials.HMACSecretHex {
		t.Fatalf("key set entry %+v %v", e, ok)
	}
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers", "", body, nil, nil); code != http.StatusConflict {
		t.Fatalf("duplicate id: %d", code)
	}

	// The receiver's own endpoints.
	var cfg map[string]any
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01/config", c.Credentials.BearerKey, "", nil, &cfg); code != http.StatusOK ||
		cfg["status"] != "enabled" || cfg["signature_header"] != receivers.SignatureHeader {
		t.Fatalf("config: %d %v", code, cfg)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-other/config", c.Credentials.BearerKey, "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("another receiver's config: %d", code)
	}
	hb := heartbeat("rx-tbs-01", "hb-1", 41.7151, 44.8271)
	var ackHB map[string]any
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/heartbeat", c.Credentials.BearerKey, hb, c.secret(t), &ackHB); code != http.StatusOK ||
		ackHB["position_deviation_m"].(float64) > 1 {
		t.Fatalf("heartbeat: %d %v", code, ackHB)
	}
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/heartbeat", c.Credentials.BearerKey, hb, c.secret(t), nil); code != http.StatusConflict {
		t.Fatalf("replayed heartbeat: %d", code)
	}
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/heartbeat", c.Credentials.BearerKey,
		heartbeat("rx-tbs-01", "hb-2", 41.7151, 44.8271), nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("unsigned heartbeat: %d", code)
	}
	// T2: reported 1.1 km away from the pinned position: counted.
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/heartbeat", c.Credentials.BearerKey,
		heartbeat("rx-tbs-01", "hb-3", 41.7251, 44.8271), c.secret(t), &ackHB); code != http.StatusOK || ackHB["position_deviation_m"].(float64) < 1000 {
		t.Fatalf("moved heartbeat: %d %v", code, ackHB)
	}
	rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01", "", "", nil, &got)
	if got["position_deviations"] != 1.0 || got["firmware"] != "rx-fw 1.2" || got["last_seen_at"] == nil {
		t.Fatalf("after heartbeats: %v", got)
	}

	// Disable, then enable: the key set says who and why.
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/status", "", `{"status":"disabled","reason":"SC-08"}`, nil, &got); code != http.StatusOK ||
		got["disabled_by"] != "admin-1" {
		t.Fatalf("disable: %d %v", code, got)
	}
	if e, _ := entry("rx-tbs-01"); e.Enabled() || *e.DisabledBy != "admin-1" || *e.DisabledReason != "SC-08" {
		t.Fatalf("disabled entry %+v", e)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01/config", c.Credentials.BearerKey, "", nil, &cfg); code != http.StatusOK || cfg["status"] != "disabled" {
		t.Fatalf("config while disabled: %d %v", code, cfg)
	}
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/status", "", `{"status":"enabled","reason":"back"}`, nil, &got); code != http.StatusOK ||
		got["status"] != "enabled" {
		t.Fatalf("enable: %d %v", code, got)
	}

	// Rotate with a grace: both keys work; then without: the old is revoked.
	var c2 creds
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/keys/rotate", "", `{"grace_s":600}`, nil, &c2); code != http.StatusOK ||
		c2.Credentials.Generation != 2 || c2.Receiver["previous_key_valid_until"] == nil {
		t.Fatalf("rotate: %d %+v", code, c2)
	}
	for _, k := range []string{c.Credentials.BearerKey, c2.Credentials.BearerKey} {
		if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01/config", k, "", nil, nil); code != http.StatusOK {
			t.Fatalf("in grace: %d", code)
		}
	}
	if e, _ := entry("rx-tbs-01"); len(e.Keys) != 2 {
		t.Fatalf("rotated entry %+v", e)
	}
	var c3 creds
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers/rx-tbs-01/keys/rotate", "", `{"grace_s":0}`, nil, &c3); code != http.StatusOK || c3.Credentials.Generation != 3 {
		t.Fatalf("rotate now: %d", code)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01/config", c2.Credentials.BearerKey, "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked key: %d", code)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01/config", c3.Credentials.BearerKey, "", nil, nil); code != http.StatusOK {
		t.Fatalf("new key: %d", code)
	}

	// Raw frames: refused without purpose or over 24 h; read with a purpose.
	ts := storetest.Open(t, m["TS_URL"])
	payload := []byte{0x12, 1, 2, 3}
	if _, err := ts.Exec(`INSERT INTO rid_observations (ingest_ts, frame_id, receiver_id, transmitter, payload, payload_sha256, backlog, sent_at_ms, nonce)
		VALUES (now(), '00112233445566778899aabbccddeeff', 'rx-tbs-01', 'AA:BB:CC:00:00:01', $1, decode(repeat('00', 32), 'hex'), false, 1, 'n')`, payload); err != nil {
		t.Fatal(err)
	}
	from, to := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	var page struct {
		Frames []map[string]any `json:"frames"`
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/frames?from="+from+"&to="+to+"&purpose=incident%2042", "", "", nil, &page); code != http.StatusOK ||
		len(page.Frames) != 1 || page.Frames[0]["payload_hex"] != hex.EncodeToString(payload) {
		t.Fatalf("frames: %d %+v", code, page)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/frames?from="+from+"&to="+to+"&transmitter=aa:bb:cc:00:00:01&purpose=case", "", "", nil, &page); code != http.StatusOK ||
		len(page.Frames) != 1 {
		t.Fatalf("frames by transmitter, lower case: %d %+v", code, page)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/frames?from="+from+"&to="+to, "", "", nil, nil); code != http.StatusBadRequest {
		t.Fatalf("frames without purpose: %d", code)
	}
	far := time.Now().Add(-49 * time.Hour).UTC().Format(time.RFC3339)
	var problem map[string]any
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/frames?from="+far+"&to="+to+"&purpose=x", "", "", nil, &problem); code != http.StatusBadRequest ||
		!strings.HasSuffix(problem["type"].(string), "/window_too_large") {
		t.Fatalf("a 50 h window: %d %v", code, problem)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/frames/00112233445566778899aabbccddeeff?purpose=check", "", "", nil, &page); code != http.StatusOK || len(page.Frames) != 1 {
		t.Fatalf("frame by id: %d", code)
	}

	// Delete: the entry goes and the keys stop working.
	if code, _ := rxCall(t, http.MethodDelete, base+"/v1/rid/receivers/rx-tbs-01?reason=decommissioned", "", "", nil, nil); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if _, ok := entry("rx-tbs-01"); ok {
		t.Fatal("the deleted receiver is still in the key set")
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-tbs-01/config", c3.Credentials.BearerKey, "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("deleted receiver's key: %d", code)
	}

	// Every step is an events row.
	db := storetest.Open(t, m["PG_URL_FOR_TEST"])
	rows, err := db.Query(`SELECT event_type, count(*) FROM events WHERE entity_type IN ('rid_receiver', 'rid_observations') GROUP BY event_type`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	counts := map[string]int{}
	for rows.Next() {
		var et string
		var n int
		if err := rows.Scan(&et, &n); err != nil {
			t.Fatal(err)
		}
		counts[et] = n
	}
	want := map[string]int{"rid_receiver_created": 1, "rid_receiver_position_deviation": 1, "rid_receiver_status_changed": 2,
		"rid_receiver_keys_rotated": 2, "rid_frames_viewed": 3, "rid_receiver_deleted": 1}
	for et, n := range want {
		if counts[et] != n {
			t.Errorf("%s: %d events, want %d (all %v)", et, counts[et], n, counts)
		}
	}
	var purpose string
	if err := db.QueryRow(`SELECT purpose FROM events WHERE event_type = 'rid_frames_viewed' ORDER BY id LIMIT 1`).Scan(&purpose); err != nil || purpose != "incident 42" {
		t.Fatalf("frames purpose %q %v", purpose, err)
	}
}

// B-09, E-01 twin of the lifecycle: with the key-set store unreachable a
// registration is refused with 503 and nothing is recorded.
func TestIntegrationReceiverChangeRefusedWithoutTheKeyStore(t *testing.T) {
	base, m, _ := startAPI(t, func(m map[string]string) { m["RID_KV_TIMEOUT_MS"] = "300" })
	if !strings.HasSuffix(m["NATS_URL"], ":1") {
		t.Fatalf("this test needs the unreachable bus of baseEnv, got %s", m["NATS_URL"])
	}
	var problem map[string]any
	body := `{"id":"rx-nobus","label":"No bus","lat_deg":41.7,"lon_deg":44.8,"owner":"authority"}`
	if code, _ := rxCall(t, http.MethodPost, base+"/v1/rid/receivers", "", body, nil, &problem); code != http.StatusServiceUnavailable ||
		!strings.HasSuffix(problem["type"].(string), "/key_store_unavailable") {
		t.Fatalf("create without the bus: %d %v", code, problem)
	}
	if code, _ := rxCall(t, http.MethodGet, base+"/v1/rid/receivers/rx-nobus", "", "", nil, nil); code != http.StatusNotFound {
		t.Fatalf("the refused receiver exists: %d", code)
	}
	db := storetest.Open(t, m["PG_URL_FOR_TEST"])
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM events WHERE entity_type = 'rid_receiver'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("events %d %v", n, err)
	}
}
