package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/rootxkit/uspace-core/auth"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/bus/bustest"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// roleHeader picks the test session's role, so one api serves an admin
// and a viewer side by side (SC-08 step 6).
const roleHeader = "X-Test-Role"

func byRole(r *http.Request) (apiserver.Identity, error) {
	role := r.Header.Get(roleHeader)
	if role == "" {
		role = apiserver.RoleAdmin
	}
	return apiserver.Identity{ActorType: "user", Subject: role + "-1", Roles: []string{role}, Realm: "console", Session: true}, nil
}

// process runs spec until the test ends; it fails the test on a
// non-zero exit and prints the process's last lines.
func process(t *testing.T, spec proc.Spec, m map[string]string) *lines {
	t.Helper()
	var stdout, stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, spec, nil, &stdout, &stderr, env(m)) }()
	t.Cleanup(func() {
		cancel()
		select {
		case code := <-exit:
			if code != proc.ExitOK {
				t.Errorf("%s exit %d; last lines of stdout:\n%s\nstderr:\n%s", spec.Name, code, stdout.tail(40), stderr.tail(40))
			}
		case <-time.After(20 * time.Second):
			t.Errorf("%s did not stop", spec.Name)
		}
	})
	return &stdout
}

func roleCall(t *testing.T, method, url, role, body string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if role != "" {
		req.Header.Set(roleHeader, role)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode
}

func observationBatch(id, nonce string) string {
	p := make([]byte, 25)
	p[0] = 0x12
	obs := fmt.Sprintf(`{"transmitter":"AA:BB:CC:00:00:03","payload_hex":%q,"rssi_dbm":-70,"rx_ts":%q}`,
		hex.EncodeToString(p), time.Now().UTC().Format("2006-01-02T15:04:05.000Z"))
	return fmt.Sprintf(`{"receiver_id":%q,"sent_at_ms":%d,"nonce":%q,"backlog":false,"observations":[%s]}`, id, time.Now().UnixMilli(), nonce, obs)
}

type sourceView struct {
	SourceType    string           `json:"source_type"`
	InstanceID    string           `json:"instance_id"`
	Switch        string           `json:"switch"`
	DisabledBy    string           `json:"disabled_by"`
	DisabledByWho string           `json:"disabled_by_who"`
	Health        string           `json:"health"`
	Counters      map[string]int64 `json:"counters"`
}

type overview struct {
	Epoch    string           `json:"epoch"`
	Version  int64            `json:"version"`
	Controls []map[string]any `json:"controls"`
	Sources  []sourceView     `json:"sources"`
}

func (o overview) source(typ, inst string) (sourceView, bool) {
	for _, s := range o.Sources {
		if s.SourceType == typ && s.InstanceID == inst {
			return s, true
		}
	}
	return sourceView{}, false
}

// SC-08 steps 2, 3, 6 and 7 through api and rid-ingest as processes on
// real PostgreSQL and NATS (the alert clearing is WP-12's):
//
//  2. direct_rid switched off by type: within a second the receiver's
//     batches are refused with 503 and Retry-After, its status says
//     disabled by type and by whom, and the console's /v1/sources shows
//     it disabled by type, by the admin, with its refusals rising;
//  3. switched on: its batches are accepted again within a second;
//  6. a viewer's switch is 403, beside the admin's 200;
//  7. every switch is an events row with the actor and the reason.
func TestIntegrationSC08SourceSwitchesThroughAPIAndRIDIngest(t *testing.T) {
	natsURL := bustest.URL(t)
	scBucket, scSubject, keys := bustest.Name("sc_api"), "ctltest."+bustest.Name("sources"), bustest.Name("rid_keys_sc08")
	nc, js := bustest.Connect(t)
	t.Cleanup(func() {
		_ = js.DeleteKeyValue(context.Background(), scBucket)
		_ = js.DeleteKeyValue(context.Background(), keys)
	})
	pg := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, pg)
	shared := map[string]string{
		"NATS_URL": natsURL, "SOURCE_CONTROL_BUCKET": scBucket, "SOURCE_CONTROL_SUBJECT": scSubject,
		"RID_KEYSET_BUCKET": keys, "SOURCE_CONTROL_REREAD_S": "1", "NATS_START_BACKOFF_MS": "10",
	}
	for k, v := range shared {
		m[k] = v
	}
	api := process(t, specWith(&config.API{}, byRole), m)
	base := "http://" + api.waitFor(t, "public listener open", nil)["addr"].(string)

	// A receiver, registered through the API.
	var c creds
	if code := roleCall(t, http.MethodPost, base+"/v1/rid/receivers", "", `{"id":"rx-sc08","label":"SC-08","lat_deg":41.7151,"lon_deg":44.8271,"owner":"authority"}`, &c); code != http.StatusCreated {
		t.Fatalf("create receiver: %d", code)
	}
	secret, _ := hex.DecodeString(c.Credentials.HMACSecretHex)

	// rid-ingest, as a process.
	rcfg := &config.RIDIngest{}
	rm := map[string]string{
		"TS_URL": "postgres://unused@127.0.0.1:1/unused", "RID_INGEST_ADDR": "127.0.0.1:0", "ADMIN_ADDR": "127.0.0.1:0",
		"STATUS_INTERVAL_S": "1", "SHUTDOWN_TIMEOUT_S": "5", "RID_INGEST_STATUS_INTERVAL_MS": "200", "RID_INGEST_KEYSET_REREAD_S": "1",
	}
	for k, v := range shared {
		rm[k] = v
	}
	rx := process(t, proc.Spec{Name: "rid-ingest", Config: rcfg, Run: func(ctx context.Context, rt *proc.Runtime) error {
		return ingest.Run(ctx, rt, rcfg, ingest.Options{})
	}}, rm)
	ingestURL := "http://" + rx.waitFor(t, "public listener open", nil)["addr"].(string) + "/v1/rid/observations"
	n := 0
	post := func() (int, http.Header) {
		n++
		body := observationBatch("rx-sc08", fmt.Sprintf("n-%d", n))
		req, _ := http.NewRequest(http.MethodPost, ingestURL, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+c.Credentials.BearerKey)
		req.Header.Set(receivers.SignatureHeader, auth.SignReport(secret, []byte(body)))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	within := func(what string, d time.Duration, ok func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for !ok() {
			if time.Since(start) > d {
				t.Fatalf("%s: not within %s", what, d)
			}
			time.Sleep(20 * time.Millisecond)
		}
		return time.Since(start)
	}
	if code, _ := post(); code != http.StatusAccepted {
		t.Fatalf("before any switch: %d", code)
	}

	// The receiver's own status, as the console's feed sees it.
	statuses := make(chan *nats.Msg, 64)
	sub, err := nc.ChanSubscribe("src.v1.direct_rid.rx-sc08", statuses)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	// Step 6 first half: a viewer cannot switch; nothing changes.
	var problem map[string]any
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid", apiserver.RoleViewer, `{"enabled":false,"reason":"viewer try"}`, &problem); code != http.StatusForbidden {
		t.Fatalf("viewer: %d %v", code, problem)
	}

	// Step 2: off by type, as an admin.
	var res map[string]any
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid", "", `{"enabled":false,"reason":"SC-08 step 2"}`, &res); code != http.StatusOK || res["changed"] != true {
		t.Fatalf("admin switch off: %d %v", code, res)
	}
	took := within("refused after the switch", time.Second, func() bool { code, _ := post(); return code == http.StatusServiceUnavailable })
	t.Logf("SC-08 step 2: refused %s after the switch committed", took)
	code, hdr := post()
	if code != http.StatusServiceUnavailable || hdr.Get("Retry-After") == "" {
		t.Fatalf("refusal %d %v", code, hdr)
	}
	within("status disabled by type, by admin", 5*time.Second, func() bool {
		select {
		case msg := <-statuses:
			var env struct {
				Body struct {
					State         string            `json:"state"`
					DisabledBy    *string           `json:"disabled_by"`
					DisabledByWho *string           `json:"disabled_by_who"`
					Counters      map[string]uint64 `json:"counters"`
				} `json:"body"`
			}
			_ = json.Unmarshal(msg.Data, &env)
			b := env.Body
			return b.State == "disabled" && b.DisabledBy != nil && *b.DisabledBy == "type" && b.DisabledByWho != nil &&
				*b.DisabledByWho == "admin-1" && b.Counters["refused"] >= 2
		default:
			return false
		}
	})
	var ov overview
	var first int64
	within("console shows disabled by type, by admin", 5*time.Second, func() bool {
		roleCall(t, http.MethodGet, base+"/v1/sources", "", "", &ov)
		s, ok := ov.source("direct_rid", "rx-sc08")
		first = s.Counters["refused"]
		return ok && s.Switch == "disabled" && s.DisabledBy == "type" && s.DisabledByWho == "admin-1" && first >= 2
	})
	post()
	post()
	within("refusal count rising on the console", 5*time.Second, func() bool {
		roleCall(t, http.MethodGet, base+"/v1/sources", "", "", &ov)
		s, _ := ov.source("direct_rid", "rx-sc08")
		return s.Counters["refused"] > first
	})

	// Step 3: on again; accepted within a second.
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid", "", `{"enabled":true,"reason":"SC-08 step 3"}`, &res); code != http.StatusOK {
		t.Fatalf("switch on: %d %v", code, res)
	}
	took = within("accepted after switching on", time.Second, func() bool { code, _ := post(); return code == http.StatusAccepted })
	t.Logf("SC-08 step 3: accepted %s after the switch committed", took)

	// One instance off, its type on: refused, then on again.
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid/rx-sc08", "", `{"enabled":false,"reason":"one receiver"}`, &res); code != http.StatusOK {
		t.Fatalf("instance off: %d %v", code, res)
	}
	within("instance refused", time.Second, func() bool { code, _ := post(); return code == http.StatusServiceUnavailable })
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid/rx-sc08", "", `{"enabled":true,"reason":"one receiver back"}`, &res); code != http.StatusOK {
		t.Fatalf("instance on: %d", code)
	}
	within("instance accepted", time.Second, func() bool { code, _ := post(); return code == http.StatusAccepted })

	// Step 6 second half: the viewer is still refused after the admin's
	// switches, and reading /v1/sources is the admin's too.
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid/rx-sc08", apiserver.RoleViewer, `{"enabled":false,"reason":"viewer try"}`, nil); code != http.StatusForbidden {
		t.Fatalf("viewer instance switch: %d", code)
	}
	if code := roleCall(t, http.MethodGet, base+"/v1/sources", apiserver.RoleViewer, "", nil); code != http.StatusForbidden {
		t.Fatalf("viewer read: %d", code)
	}

	// Step 7: every switch is an events row with the actor and the
	// reason; the viewer's attempts are not.
	db := storetest.Open(t, pg)
	rows, err := db.Query(`SELECT event_type, actor_id, entity_id, payload->>'reason' FROM events WHERE entity_type = 'source' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var et, actor, entity, reason string
		if err := rows.Scan(&et, &actor, &entity, &reason); err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.Join([]string{et, actor, entity, reason}, "|"))
	}
	want := []string{
		"source_disabled|admin-1|direct_rid/*|SC-08 step 2",
		"source_enabled|admin-1|direct_rid/*|SC-08 step 3",
		"source_disabled|admin-1|direct_rid/rx-sc08|one receiver",
		"source_enabled|admin-1|direct_rid/rx-sc08|one receiver back",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("events:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// SC-08 step 8, E-02: a follower started while the shared store is
// unavailable tries three times with backoff, then starts with every
// source enabled and says the switch state is unknown; a switch
// attempted meanwhile is refused with 503 and nothing changes.
func TestIntegrationSC08FollowerStartsEnabledWithoutTheStoreAndSwitchesAreRefused(t *testing.T) {
	pg := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, pg) // NATS_URL is a port nothing listens on
	m["NATS_TIMEOUT_MS"] = "200"
	api := process(t, specWith(&config.API{}, byRole), m)
	api.waitFor(t, "source-control state unknown: every source is enabled until it can be read (B-09)", func(l map[string]any) bool {
		return l["attempts"] == 3.0
	})
	retries := 0
	api.find("source-control state not readable; retrying", func(map[string]any) bool { retries++; return false })
	if retries != 2 {
		t.Fatalf("%d retries logged before starting, want 2 (three attempts)", retries)
	}
	base := "http://" + api.waitFor(t, "public listener open", nil)["addr"].(string)
	var problem map[string]any
	if code := roleCall(t, http.MethodPut, base+"/v1/sources/direct_rid", "", `{"enabled":false,"reason":"while the store is down"}`, &problem); code != http.StatusServiceUnavailable ||
		!strings.HasSuffix(problem["type"].(string), "/source_control_unavailable") {
		t.Fatalf("switch without the store: %d %v", code, problem)
	}
	var ov overview
	if code := roleCall(t, http.MethodGet, base+"/v1/sources", "", "", &ov); code != http.StatusOK || len(ov.Controls) != 0 || ov.Version != 0 {
		t.Fatalf("the refused switch changed something: %d %+v", code, ov)
	}
	var n int
	if err := storetest.Open(t, pg).QueryRow(`SELECT count(*) FROM events WHERE entity_type = 'source'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("events %d %v", n, err)
	}
	api.waitFor(t, "status", func(l map[string]any) bool { return l["source_control_known"] == false && l["nats"] != "CONNECTED" })
}

// GET and PUT /v1/cells through the process: the admin's map is stored
// with its version and audited; a viewer is refused.
func TestIntegrationCellOwnershipThroughTheAPI(t *testing.T) {
	_, js := bustest.Connect(t)
	pg := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, pg)
	m["NATS_URL"] = bustest.URL(t)
	api := process(t, specWith(&config.API{}, byRole), m)
	base := "http://" + api.waitFor(t, "public listener open", nil)["addr"].(string)
	kv, err := js.KeyValue(context.Background(), "cells")
	if err == nil {
		_ = kv.Purge(context.Background(), "ownership")
	}
	if code := roleCall(t, http.MethodGet, base+"/v1/cells", "", "", nil); code != http.StatusNotFound {
		t.Fatalf("before any map: %d", code)
	}
	var o map[string]any
	if code := roleCall(t, http.MethodPut, base+"/v1/cells", "", `{"assignments":{"c3:131:224":"detect-1"},"reason":"initial"}`, &o); code != http.StatusOK || o["version"] != 1.0 {
		t.Fatalf("put: %d %v", code, o)
	}
	if code := roleCall(t, http.MethodGet, base+"/v1/cells", "", "", &o); code != http.StatusOK || o["updated_by"] != "admin-1" {
		t.Fatalf("get: %d %v", code, o)
	}
	if code := roleCall(t, http.MethodPut, base+"/v1/cells", apiserver.RoleViewer, `{"assignments":{},"reason":"x"}`, nil); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	var problem map[string]any
	if code := roleCall(t, http.MethodPut, base+"/v1/cells", "", `{"assignments":{"c5:1317:2248":"detect-1"},"reason":"x"}`, &problem); code != http.StatusBadRequest {
		t.Fatalf("a c5 key: %d %v", code, problem)
	}
	var n int
	if err := storetest.Open(t, pg).QueryRow(`SELECT count(*) FROM events WHERE event_type = 'cell_ownership_changed' AND actor_id = 'admin-1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("events %d %v", n, err)
	}
}
