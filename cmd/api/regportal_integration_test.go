package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/config"
	"github.com/rootxkit/uspace-authority/internal/proc"
	"github.com/rootxkit/uspace-authority/internal/store/migrate"
	"github.com/rootxkit/uspace-authority/internal/store/storetest"
)

// relay is a loopback SMTP relay keeping the bodies it is sent; arrived
// is signalled after each one is kept.
type relay struct {
	mu      sync.Mutex
	msgs    []string
	arrived chan struct{}
	l       net.Listener
}

func newRelay(t *testing.T) *relay {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{l: l, arrived: make(chan struct{}, 1)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *relay) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	rd := bufio.NewReader(c)
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	say("220 test relay")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		switch strings.ToUpper(strings.TrimSpace(line)) {
		case "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil || l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			_, body, _ := strings.Cut(b.String(), "\r\n\r\n")
			dec, _ := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
			r.mu.Lock()
			r.msgs = append(r.msgs, string(dec))
			r.mu.Unlock()
			select {
			case r.arrived <- struct{}{}:
			default: // a signal is pending already; the waiter reads the count
			}
			say("250 queued")
		case "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// waitMail waits until the relay holds n messages and returns the last,
// woken by each arrival rather than polling.
func (r *relay) waitMail(t *testing.T, n int) string {
	t.Helper()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	for {
		r.mu.Lock()
		if len(r.msgs) >= n {
			m := r.msgs[n-1]
			r.mu.Unlock()
			return m
		}
		r.mu.Unlock()
		select {
		case <-r.arrived:
		case <-deadline.C:
			t.Fatalf("no message %d", n)
			return ""
		}
	}
}

func linkToken(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`#token=(\S+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no link in %q", body)
	}
	tok, err := url.QueryUnescape(m[1])
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// send makes one request with headers and returns the status and the
// decoded body.
func sendPortal(t *testing.T, method, u, contentType, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, u, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func startPortalAPI(t *testing.T, m map[string]string) (base string, stdout *lines) {
	t.Helper()
	identify := func(*http.Request) (apiserver.Identity, error) {
		return apiserver.Identity{ActorType: "user", Subject: "registrar-1", Roles: []string{apiserver.RoleRegistrar}, Realm: "console", Session: true}, nil
	}
	stdout = &lines{}
	var stderr lines
	ctx, cancel := context.WithCancel(context.Background())
	exit := make(chan int, 1)
	go func() { exit <- proc.Main(ctx, specWith(&config.API{}, identify), nil, stdout, &stderr, env(m)) }()
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
	stdout.waitFor(t, "status", func(l map[string]any) bool { return l["policy_version"] == 1.0 })
	return "http://" + listen["addr"].(string), stdout
}

func copyTestdata(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "regimport", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readTestdata(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "regimport", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// WP-20 through the real process with the portal flags off (the
// default): the import runs under the rules file (dry run, refusal,
// import, idempotent re-import), the public check answers status only
// and is rate-limited, and every portal operation is 404.
func TestIntegrationRegistryImportAndCheckThroughTheProcess(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	m["REGISTRY_IMPORT_RULES_FILE"] = copyTestdata(t, t.TempDir(), "rules.json")
	m["REGISTRY_CHECK_PER_MIN"], m["REGISTRY_CHECK_BURST"] = "1", "3"
	base, stdout := startPortalAPI(t, m)
	if l := stdout.find("registry portal", nil); l == nil || l["applications"] != "off" || l["import_rules"] != true || l["reimport"] != false {
		t.Fatalf("start line %v", l)
	}
	ops := readTestdata(t, "operators.csv")
	code, rep := sendPortal(t, http.MethodPost, base+"/v1/registry/import?kind=operators&dry_run=true", "text/csv", ops, nil)
	if code != http.StatusOK || rep["dry_run"] != true || rep["applied"] != false || rep["created"] != 2.0 {
		t.Fatalf("dry run %d %v", code, rep)
	}
	code, prob := sendPortal(t, http.MethodPost, base+"/v1/registry/import?kind=operators", "text/csv", strings.Replace(ops, "Test Person", "", 1), nil)
	if code != http.StatusUnprocessableEntity || !strings.Contains(mustJSON(prob["errors"]), "records[1].full_name") ||
		!strings.Contains(mustJSON(prob["errors"]), `column \"Name\"`) {
		t.Fatalf("refused %d %v", code, prob)
	}
	code, rep = sendPortal(t, http.MethodPost, base+"/v1/registry/import?kind=operators", "text/csv", ops, nil)
	if code != http.StatusOK || rep["applied"] != true || rep["created"] != 2.0 {
		t.Fatalf("import %d %v", code, rep)
	}
	uasJSON := `[{"Record ID":"TEST-UAS-1","Serial":"TESTA0123456789","Operator":"GEOTEST00000001","Class":"C1","Mass kg":0.8,"Remote ID":"broadcast","Status":"Active"}]`
	code, rep = sendPortal(t, http.MethodPost, base+"/v1/registry/import?kind=uas", "application/json", uasJSON, nil)
	if code != http.StatusOK || rep["created"] != 1.0 {
		t.Fatalf("uas %d %v", code, rep)
	}
	code, rep = sendPortal(t, http.MethodPost, base+"/v1/registry/import?kind=operators", "text/csv", ops, nil)
	if code != http.StatusOK || rep["unchanged"] != 2.0 || rep["created"] != 0.0 {
		t.Fatalf("re-import %d %v", code, rep)
	}
	if code, _ := sendPortal(t, http.MethodPost, base+"/v1/registry/import?kind=operators", "text/plain", ops, nil); code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain %d", code)
	}

	// The public check: status only, secret part stripped, budget per
	// address.
	code, chk := sendPortal(t, http.MethodGet, base+"/v1/registry/check?number=geotest00000001-x9z", "", "", nil)
	if code != http.StatusOK || chk["status"] != "valid" || chk["valid_until"] == nil || len(chk) != 2 {
		t.Fatalf("check %d %v", code, chk)
	}
	if code, chk := sendPortal(t, http.MethodGet, base+"/v1/registry/check?number=GEOTEST00000002", "", "", nil); code != http.StatusOK || chk["status"] != "suspended" {
		t.Fatalf("suspended %d %v", code, chk)
	}
	if code, chk := sendPortal(t, http.MethodGet, base+"/v1/registry/check?number=GEOTEST00000099", "", "", nil); code != http.StatusOK || chk["status"] != "unknown" {
		t.Fatalf("unknown %d %v", code, chk)
	}
	if code, _ := sendPortal(t, http.MethodGet, base+"/v1/registry/check?number=GEOTEST00000099", "", "", nil); code != http.StatusTooManyRequests {
		t.Fatalf("past the budget %d", code)
	}
	// The portal is off: 404 for every one of its operations.
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/v1/registry/applications", `{"operator_type":"natural","postal_address":"x","contact_email":"a@example.test","contact_phone":"+995 1","lang":"en"}`},
		{http.MethodGet, "/v1/registry/applications", ""},
		{http.MethodPost, "/v1/registry/operator-links", `{"registration_number":"GEOTEST00000001"}`},
	} {
		ct := ""
		if c.body != "" {
			ct = "application/json"
		}
		if code, _ := sendPortal(t, c.method, base+c.path, ct, c.body, nil); code != http.StatusNotFound {
			t.Errorf("%s %s: %d", c.method, c.path, code)
		}
	}
}

// WP-20 through the real process with both flags on: an application is
// verified by its mailed link, approved, and the number it was issued
// checks valid; an operator's link takes one occurrence report into
// WP-18's intake and refuses a second.
func TestIntegrationRegistryPortalThroughTheProcess(t *testing.T) {
	u := storetest.Migrated(t, migrate.Relational)
	m := baseEnv(t, u)
	dir := t.TempDir()
	r := newRelay(t)
	m["REGISTRY_APPLICATIONS"], m["REGISTRY_OPERATOR_REPORTS"] = "on", "on"
	m["REGISTRY_PORTAL_KEY_FILE"] = writeKey(t, dir, "portal.key")
	m["REGISTRY_PORTAL_URL"] = "https://portal.example.test"
	m["REGISTRY_MAIL_SMTP_ADDR"], m["REGISTRY_MAIL_TLS"], m["REGISTRY_MAIL_FROM"] = r.l.Addr().String(), "none", "portal@example.test"
	m["REGISTRY_MAIL_EVERY_S"] = "1"
	m["OCCURRENCE_KEY_FILE"] = writeKey(t, dir, "occurrence.key")
	base, _ := startPortalAPI(t, m)

	app := `{"operator_type":"natural","full_name":"Test Applicant","date_of_birth":"1985-03-04","postal_address":"3 Test Street",
		"contact_email":"applicant@example.test","contact_phone":"+995 555 000 003","lang":"en"}`
	code, st := sendPortal(t, http.MethodPost, base+"/v1/registry/applications", "application/json", app, nil)
	if code != http.StatusAccepted || st["state"] != "unverified" {
		t.Fatalf("submit %d %v", code, st)
	}
	id := st["application_id"].(string)
	tok := linkToken(t, r.waitMail(t, 1))
	hdr := map[string]string{"X-Application-Token": tok}
	if code, st := sendPortal(t, http.MethodPost, base+"/v1/registry/applications/"+id+"/verify", "", "", hdr); code != http.StatusOK || st["state"] != "submitted" {
		t.Fatalf("verify %d %v", code, st)
	}
	if code, _ := sendPortal(t, http.MethodGet, base+"/v1/registry/applications/"+id, "", "", map[string]string{"X-Application-Token": tok + "x"}); code != http.StatusNotFound {
		t.Fatalf("forged token %d", code)
	}
	if code, _ := sendPortal(t, http.MethodPost, base+"/v1/registry/applications/"+id+"/review", "", "", nil); code != http.StatusOK {
		t.Fatalf("review %d", code)
	}
	code, ap := sendPortal(t, http.MethodPost, base+"/v1/registry/applications/"+id+"/approve", "application/json", `{}`, nil)
	if code != http.StatusOK || ap["state"] != "approved" || ap["registration_number"] == nil {
		t.Fatalf("approve %d %v", code, ap)
	}
	number := ap["registration_number"].(string)
	if strings.Contains(mustJSON(ap), "secret") {
		t.Fatalf("a secret in the response: %v", ap)
	}
	approval := r.waitMail(t, 2)
	if !strings.Contains(approval, number+"-") {
		t.Fatalf("approval mail %q", approval)
	}
	if code, chk := sendPortal(t, http.MethodGet, base+"/v1/registry/check?number="+number, "", "", nil); code != http.StatusOK || chk["status"] != "valid" {
		t.Fatalf("check %d %v", code, chk)
	}
	if code, st := sendPortal(t, http.MethodGet, base+"/v1/registry/applications/"+id, "", "", map[string]string{"X-Application-Token": linkToken(t, approval)}); code != http.StatusOK || st["registration_number"] != number {
		t.Fatalf("status %d %v", code, st)
	}

	// The approved operator asks for its occurrence link.
	if code, _ := sendPortal(t, http.MethodPost, base+"/v1/registry/operator-links", "application/json", fmt.Sprintf(`{"registration_number":%q}`, number), nil); code != http.StatusAccepted {
		t.Fatalf("link %d", code)
	}
	op := map[string]string{"X-Operator-Token": linkToken(t, r.waitMail(t, 3))}
	report := occurrenceBody("TEST-OPERATOR-OCC-1", time.Hour)
	code, rc := sendPortal(t, http.MethodPost, base+"/v1/occurrences/operator", "application/json", report, op)
	if code != http.StatusCreated || rc["report_ref"] != "TEST-OPERATOR-OCC-1" {
		t.Fatalf("report %d %v", code, rc)
	}
	if code, p := sendPortal(t, http.MethodPost, base+"/v1/occurrences/operator", "application/json", report, op); code != http.StatusUnauthorized || !strings.HasSuffix(p["type"].(string), "/link_spent") {
		t.Fatalf("second use %d %v", code, p)
	}
}
