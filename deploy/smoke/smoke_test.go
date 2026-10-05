package smoke

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/pquerna/otp/totp"
	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/api/gen"
)

// maxBody bounds every response the driver reads.
const maxBody = 4 << 20

// requestTimeout bounds every HTTP call; acceptWithin and trackWithin
// bound the two waits on the stack (the key set reaching rid-ingest, the
// track reaching the console).
const (
	requestTimeout = 15 * time.Second
	acceptWithin   = 60 * time.Second
	trackWithin    = 60 * time.Second
)

// piiMembers are the personal-data property names spec 06 and the lab's
// policy.yaml list; none may appear in a validity answer (REG-NOPII).
var piiMembers = []string{"name", "full_name", "legal_name", "email", "contact_email", "phone", "contact_phone",
	"address", "postal_address", "date_of_birth", "legal_identification_number", "insurance_policy_number"}

type fixture struct {
	Operator map[string]any `json:"operator"`
	UAS      map[string]any `json:"uas"`
	Receiver struct {
		ID     string  `json:"id"`
		Label  string  `json:"label"`
		Owner  string  `json:"owner"`
		LatDeg float64 `json:"lat_deg"`
		LonDeg float64 `json:"lon_deg"`
	} `json:"receiver"`
	Aircraft struct {
		Transmitter string  `json:"transmitter"`
		LatDeg      float64 `json:"lat_deg"`
		LonDeg      float64 `json:"lon_deg"`
		AltAMSLM    float64 `json:"alt_amsl_m"`
	} `json:"aircraft"`
}

type settings struct {
	base, host, origin string
	stateDir           string
	adminPWFile        string
	geoidFile          string
	fixtureFile        string
	hc                 *http.Client
	tlsConf            *tls.Config
}

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s is not set (deploy/smoke/doc.go)", name)
	}
	return v
}

func load(t *testing.T) settings {
	t.Helper()
	s := settings{
		base: strings.TrimRight(mustEnv(t, "STAGING_SMOKE_URL"), "/"), stateDir: mustEnv(t, "STAGING_SMOKE_STATE_DIR"),
		adminPWFile: mustEnv(t, "STAGING_SMOKE_ADMIN_PASSWORD_FILE"), geoidFile: mustEnv(t, "STAGING_SMOKE_GEOID_FILE"),
		fixtureFile: os.Getenv("STAGING_SMOKE_FIXTURE"),
	}
	if s.fixtureFile == "" {
		s.fixtureFile = filepath.Join("..", "fixtures", "operator.json")
	}
	u, err := url.Parse(s.base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		t.Fatalf("STAGING_SMOKE_URL %q: want https://<host>[:port]", s.base)
	}
	s.host, s.origin = u.Hostname(), u.Scheme+"://"+u.Host
	s.tlsConf = &tls.Config{MinVersion: tls.VersionTLS12}
	if f := os.Getenv("STAGING_SMOKE_CA_FILE"); f != "" {
		pem, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("STAGING_SMOKE_CA_FILE: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			t.Fatal("STAGING_SMOKE_CA_FILE holds no certificate")
		}
		s.tlsConf.RootCAs = pool
	}
	tr := &http.Transport{TLSClientConfig: s.tlsConf, MaxIdleConnsPerHost: 4, ResponseHeaderTimeout: requestTimeout}
	// STAGING_SMOKE_CONNECT dials another address for the public host
	// (curl's --resolve): the name, the certificate and the Origin stay
	// the public ones.
	if addr := os.Getenv("STAGING_SMOKE_CONNECT"); addr != "" {
		d := &net.Dialer{Timeout: 5 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	}
	s.hc = &http.Client{Transport: tr, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := os.MkdirAll(s.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return s
}

// call makes one request and decodes a JSON answer into out (when the
// status is wanted); it returns the status and the raw body.
func (s settings) call(t *testing.T, method, path, bearer, ctype string, body []byte, out any) (int, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		t.Fatalf("%s %s: reading the answer: %v", method, path, err)
	}
	if out != nil && resp.StatusCode < 300 && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %d, not JSON: %.300s", method, path, resp.StatusCode, raw)
		}
	}
	return resp.StatusCode, raw
}

func jsonBody(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// readSecret reads a one-line secret file; "" when it does not exist.
func readSecret(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func writeSecret(t *testing.T, path, v string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(v+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// signIn signs a console account in (password, then TOTP) and returns
// its session token. The TOTP secret of the first sign-in (enrolment)
// is kept in totpFile; later runs read it back.
func (s settings) signIn(t *testing.T, username, password, totpFile string) string {
	t.Helper()
	var ch gen.LoginChallenge
	if code, raw := s.call(t, http.MethodPost, "/v1/auth/login", "", "application/json",
		jsonBody(t, gen.LoginRequest{Username: username, Password: password}), &ch); code != http.StatusOK {
		t.Fatalf("login %s: %d %.300s", username, code, raw)
	}
	secret := readSecret(t, totpFile)
	if ch.Enrolment != nil {
		secret = ch.Enrolment.Secret
	}
	if secret == "" {
		t.Fatalf("login %s: TOTP is enrolled and %s does not hold its secret", username, totpFile)
	}
	// A code is accepted once per 30 s step: when this step's code was
	// used by an earlier run, the next step's is inside the skew window.
	for _, at := range []time.Time{time.Now(), time.Now().Add(30 * time.Second)} {
		code6, err := totp.GenerateCode(secret, at)
		if err != nil {
			t.Fatal(err)
		}
		var sess gen.SessionIssued
		code, _ := s.call(t, http.MethodPost, "/v1/auth/mfa", "", "application/json",
			jsonBody(t, gen.MFARequest{MfaToken: ch.MfaToken, Code: &code6}), &sess)
		if code == http.StatusOK && sess.Token != "" {
			if ch.Enrolment != nil {
				writeSecret(t, totpFile, secret)
			}
			t.Logf("signed in %s (roles %v)", username, sess.Session.Roles)
			return sess.Token
		}
	}
	t.Fatalf("mfa %s: refused", username)
	return ""
}

func readFixture(t *testing.T, path string) fixture {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f
}

// jsonKeys is every object member name anywhere in a JSON document.
func jsonKeys(v any, out map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			out[k] = true
			jsonKeys(e, out)
		}
	case []any:
		for _, e := range x {
			jsonKeys(e, out)
		}
	}
}

func TestStagingSmoke(t *testing.T) {
	if os.Getenv("STAGING_SMOKE") != "1" {
		t.Skip("STAGING_SMOKE=1 not set: needs a deployed stack (deploy/smoke/run.sh)")
	}
	s := load(t)
	fx := readFixture(t, s.fixtureFile)
	number, _ := fx.Operator["registration_number"].(string)
	serial, _ := fx.UAS["serial"].(string)
	if number == "" || serial == "" {
		t.Fatalf("%s names no registration_number or serial", s.fixtureFile)
	}

	// The public front answers before anything else is tried.
	if code, raw := s.call(t, http.MethodGet, "/healthz", "", "", nil, nil); code != http.StatusOK {
		t.Fatalf("/healthz through the edge: %d %.200s", code, raw)
	}
	for _, p := range []string{"/readyz", "/metrics"} {
		if code, _ := s.call(t, http.MethodGet, p, "", "", nil, nil); code != http.StatusNotFound {
			t.Fatalf("%s through the edge: %d, want 404 (never routed)", p, code)
		}
	}

	adminPW := readSecret(t, s.adminPWFile)
	if adminPW == "" {
		t.Fatalf("%s is missing or empty", s.adminPWFile)
	}
	admin := s.signIn(t, "admin", adminPW, filepath.Join(s.stateDir, "admin.totp"))

	// A registrar for the registry writes (admin holds no registry role).
	regPWFile := filepath.Join(s.stateDir, "registrar.pw")
	regPW := readSecret(t, regPWFile)
	if regPW == "" {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		regPW = hex.EncodeToString(b[:])
	}
	code, raw := s.call(t, http.MethodPost, "/v1/users", admin, "application/json", jsonBody(t, map[string]any{
		"username": "smoke-registrar", "password": regPW, "roles": []string{"registrar"}, "realm": "console",
		"display_name": "Staging smoke registrar"}), nil)
	switch code {
	case http.StatusCreated:
		writeSecret(t, regPWFile, regPW)
		t.Log("created the console account smoke-registrar")
	case http.StatusConflict:
		if readSecret(t, regPWFile) == "" {
			t.Fatalf("smoke-registrar exists and %s does not hold its password", regPWFile)
		}
		t.Log("the console account smoke-registrar exists")
	default:
		t.Fatalf("create smoke-registrar: %d %.300s", code, raw)
	}
	registrar := s.signIn(t, "smoke-registrar", regPW, filepath.Join(s.stateDir, "registrar.totp"))

	operatorID := registerFixture(t, s, registrar, fx, number, serial)

	// Presence: the personal data is held, and read with a purpose.
	var pd map[string]any
	if code, raw := s.call(t, http.MethodGet, "/v1/registry/operators/"+url.PathEscape(operatorID)+"/personal-data?purpose=registration_review",
		registrar, "", nil, &pd); code != http.StatusOK {
		t.Fatalf("personal data: %d %.300s", code, raw)
	}
	for _, k := range []string{"contact_email", "contact_phone", "postal_address", "legal_name"} {
		if pd[k] != fx.Operator[k] {
			t.Fatalf("personal data %s: %v, want the fixture's", k, pd[k])
		}
	}
	t.Log("the operator's personal data is held and read with a purpose (registry_pii_viewed)")

	validateNoPII(t, s, admin, fx, number)
	trackID := receiverAndPicture(t, s, admin, fx, serial)

	out := map[string]string{"operator_registration_number": number, "uas_serial": serial, "operator_id": operatorID,
		"track_id": trackID, "receiver_id": fx.Receiver.ID}
	if err := os.WriteFile(filepath.Join(s.stateDir, "fixture.json"), jsonBody(t, out), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture: AUTHORITY_CONFORMANCE_OPERATOR=%s (uas %s, track %s)", number, serial, trackID)
}

// registerFixture registers the fixture's operator and UAS, or finds
// them registered (409), and returns the operator's id.
func registerFixture(t *testing.T, s settings, registrar string, fx fixture, number, serial string) string {
	t.Helper()
	var op gen.RegistryOperator
	code, raw := s.call(t, http.MethodPost, "/v1/registry/operators", registrar, "application/json", jsonBody(t, fx.Operator), &op)
	switch code {
	case http.StatusCreated:
		t.Logf("registered operator %s (%s)", number, op.Id)
	case http.StatusConflict:
		var list gen.RegistryOperatorList
		if code, raw := s.call(t, http.MethodGet, "/v1/registry/operators?number="+url.QueryEscape(number), registrar, "", nil, &list); code != http.StatusOK || len(list.Operators) != 1 {
			t.Fatalf("look up operator %s: %d %.300s", number, code, raw)
		}
		op = list.Operators[0]
		t.Logf("operator %s is registered (%s)", number, op.Id)
	default:
		t.Fatalf("register operator %s: %d %.300s", number, code, raw)
	}
	uas := map[string]any{"operator_id": op.Id}
	for k, v := range fx.UAS {
		uas[k] = v
	}
	code, raw = s.call(t, http.MethodPost, "/v1/registry/uas", registrar, "application/json", jsonBody(t, uas), nil)
	switch code {
	case http.StatusCreated:
		t.Logf("registered UAS %s", serial)
	case http.StatusConflict:
		t.Logf("UAS %s is registered", serial)
	default:
		t.Fatalf("register UAS %s: %d %.300s", serial, code, raw)
	}
	return op.Id
}

// validateNoPII asks the F8 validity of the fixture's operator with an
// ecosystem token and finds a status-only answer (REG-NOPII).
func validateNoPII(t *testing.T, s settings, admin string, fx fixture, number string) {
	t.Helper()
	secretFile := filepath.Join(s.stateDir, "lab-01.secret")
	var created gen.OAuthClientCreated
	code, raw := s.call(t, http.MethodPost, "/v1/oauth/clients", admin, "application/json", jsonBody(t, map[string]any{
		"client_id": "lab-01", "scopes": []string{"registry.validate"}, "audiences": []string{s.host},
		"auth_method": "client_secret_post", "note": "staging smoke and the lab's conformance suite"}), &created)
	switch {
	case code == http.StatusCreated && created.ClientSecret != nil:
		writeSecret(t, secretFile, *created.ClientSecret)
		t.Log("created the machine client lab-01 (registry.validate)")
	case code == http.StatusConflict && readSecret(t, secretFile) != "":
		t.Log("the machine client lab-01 exists")
	default:
		t.Fatalf("create lab-01: %d %.300s", code, raw)
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"lab-01"},
		"client_secret": {readSecret(t, secretFile)}, "scope": {"registry.validate"}, "audience": {s.host}}
	var tok gen.TokenResponse
	if code, raw := s.call(t, http.MethodPost, "/oauth/token", "", "application/x-www-form-urlencoded", []byte(form.Encode()), &tok); code != http.StatusOK {
		t.Fatalf("token for lab-01: %d %.300s", code, raw)
	}

	path := "/v1/registry/validate?purpose=identification&operator=" + url.QueryEscape(number)
	// The refusal first: without a token the same question is 401.
	if code, _ := s.call(t, http.MethodGet, path, "", "", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("validate without a token: %d, want 401", code)
	}
	var v gen.RegistryValidity
	code, raw = s.call(t, http.MethodGet, path, tok.AccessToken, "", nil, &v)
	if code != http.StatusOK || v.Operator == nil {
		t.Fatalf("validate %s: %d %.300s", number, code, raw)
	}
	if v.Operator.Status != gen.RegistryValidityStatusValid || v.Operator.RegistrationNumber != number {
		t.Fatalf("validate %s: %+v, want valid", number, *v.Operator)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	jsonKeys(doc, keys)
	for _, k := range piiMembers {
		if keys[k] {
			t.Fatalf("validate answers the personal-data member %q: %s", k, raw)
		}
	}
	for _, k := range []string{"legal_name", "contact_email", "contact_phone", "postal_address", "legal_identification_number"} {
		if val, _ := fx.Operator[k].(string); val != "" && bytes.Contains(raw, []byte(val)) {
			t.Fatalf("validate answers the fixture's %s value: %s", k, raw)
		}
	}
	t.Logf("validate %s: %s, status only (none of %d personal-data members): %s", number, v.Operator.Status, len(piiMembers), raw)
}

// receiverAndPicture registers the fixture's receiver, posts the
// aircraft's frames until rid-ingest accepts a batch, and reads the
// picture until the aircraft's track arrives. It returns the track id.
func receiverAndPicture(t *testing.T, s settings, admin string, fx fixture, serial string) string {
	t.Helper()
	keyFile := filepath.Join(s.stateDir, "receiver.json")
	var creds gen.RIDReceiverCredentials
	var created gen.RIDReceiverCreated
	code, raw := s.call(t, http.MethodPost, "/v1/rid/receivers", admin, "application/json", jsonBody(t, map[string]any{
		"id": fx.Receiver.ID, "label": fx.Receiver.Label, "owner": fx.Receiver.Owner,
		"lat_deg": fx.Receiver.LatDeg, "lon_deg": fx.Receiver.LonDeg}), &created)
	switch code {
	case http.StatusCreated:
		creds = created.Credentials
		if err := os.WriteFile(keyFile, jsonBody(t, creds), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Logf("registered receiver %s (key generation %d)", fx.Receiver.ID, creds.Generation)
	case http.StatusConflict:
		b, err := os.ReadFile(keyFile)
		if err != nil {
			t.Fatalf("receiver %s exists and %s does not hold its keys: %v", fx.Receiver.ID, keyFile, err)
		}
		if err := json.Unmarshal(b, &creds); err != nil {
			t.Fatal(err)
		}
		t.Logf("receiver %s exists", fx.Receiver.ID)
	default:
		t.Fatalf("register receiver: %d %.300s", code, raw)
	}
	secret, err := hex.DecodeString(creds.HmacSecretHex)
	if err != nil || len(secret) != 32 {
		t.Fatalf("receiver secret: %v", err)
	}
	g, err := geoid.Load(s.geoidFile)
	if err != nil {
		t.Fatalf("STAGING_SMOKE_GEOID_FILE: %v", err)
	}
	n, err := g.UndulationM(core.LatLon{LatDeg: fx.Aircraft.LatDeg, LonDeg: fx.Aircraft.LonDeg})
	if err != nil {
		t.Fatal(err)
	}
	operator, _ := fx.Operator["registration_number"].(string)
	nonce := 0
	post := func() (int, gen.RIDObservationAck, []byte) {
		now := time.Now().UTC()
		lat, lon := fx.Aircraft.LatDeg, fx.Aircraft.LonDeg
		hae := geoid.HAEFromAMSL(fx.Aircraft.AltAMSLM, n)
		baro := fx.Aircraft.AltAMSLM
		speed, dir := 0.0, 0.0
		tenths := float64(now.Sub(now.Truncate(time.Hour))/(100*time.Millisecond)) / 10
		pack, err := odid.EncodePack([]odid.Message{
			odid.BasicID{IDType: odid.IDTypeSerial, UAType: 2, UAID: serial},
			odid.Location{Status: odid.StatusAirborne, LatDeg: &lat, LonDeg: &lon, AltHAEM: &hae, AltBaroM: &baro,
				SpeedHorizontalMS: &speed, DirectionDeg: &dir, HorizAccuracy: 11, VertAccuracy: 4, BaroAccuracy: 4,
				SpeedAccuracy: 3, TSAccuracy: 2, SecondsAfterHour: &tenths},
			odid.OperatorID{OperatorIDType: 0, OperatorID: operator},
		})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		nonce++
		rx := now.Truncate(time.Millisecond)
		rssi := -70.0
		body := jsonBody(t, gen.RIDObservationBatch{ReceiverId: fx.Receiver.ID, SentAtMs: now.UnixMilli(),
			Nonce:        fmt.Sprintf("smoke-%d-%d", now.UnixNano(), nonce),
			Observations: []gen.RIDObservation{{Transmitter: fx.Aircraft.Transmitter, PayloadHex: hex.EncodeToString(pack), RssiDbm: &rssi, RxTs: &rx}}})
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/v1/rid/observations", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+creds.BearerKey)
		req.Header.Set(string(creds.SignatureHeader), auth.SignReport(secret, body))
		resp, err := s.hc.Do(req)
		if err != nil {
			t.Fatalf("post observations: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		var ack gen.RIDObservationAck
		if resp.StatusCode == http.StatusAccepted {
			_ = json.Unmarshal(raw, &ack)
		}
		return resp.StatusCode, ack, raw
	}

	// rid-ingest follows the key set api writes: the receiver's first
	// batches may arrive before the key does and are refused 401. Each
	// batch has a nonce of its own, a refused one writes nothing, and
	// the wait is bounded.
	deadline := time.Now().Add(acceptWithin)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	refused := 0
	for {
		code, ack, raw := post()
		if code == http.StatusAccepted && ack.Accepted == 1 {
			t.Logf("rid-ingest accepted a batch (202, %s) after %d refused while the key set reached it", ack.BatchId, refused)
			break
		}
		if code != http.StatusUnauthorized || time.Now().After(deadline) {
			t.Fatalf("post observations: %d %.300s (after %d refused)", code, raw, refused)
		}
		refused++
		<-tick.C
	}

	trackID := rid.AircraftID(odid.IDTypeSerial, serial)
	ctx, cancel := context.WithTimeout(context.Background(), trackWithin+requestTimeout)
	defer cancel()
	wsURL := "wss://" + strings.TrimPrefix(s.base, "https://") + "/v1/picture/ws"
	c, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPClient: s.hc, HTTPHeader: http.Header{
		"Origin": {s.origin}, "Cookie": {"uspace_session=" + admin},
	}})
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		t.Fatalf("picture WebSocket: %d %v", status, err)
	}
	defer func() { _ = c.CloseNow() }()
	c.SetReadLimit(1 << 24)
	frames := make(chan string, 256)
	go func() {
		defer close(frames)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			select {
			case frames <- string(b):
			default: // the reader below is behind; the next frames say the same
			}
		}
	}()
	seen := map[string]int{}
	// read waits for a frame that satisfies ok, keeping the aircraft on
	// the air (one batch a second) while it waits.
	read := func(what string, ok func(schema, frame string) bool) {
		t.Helper()
		deadline := time.After(trackWithin)
		for {
			select {
			case f, open := <-frames:
				if !open {
					t.Fatalf("the picture stream closed before %s; frames seen %v", what, seen)
				}
				var env struct {
					Schema string `json:"schema"`
				}
				_ = json.Unmarshal([]byte(f), &env)
				seen[env.Schema]++
				if ok(env.Schema, f) {
					return
				}
			case <-tick.C:
				if code, _, raw := post(); code != http.StatusAccepted {
					t.Fatalf("post observations: %d %.300s", code, raw)
				}
			case <-deadline:
				t.Fatalf("no %s within %s; frames seen %v", what, trackWithin, seen)
			}
		}
	}
	read("console/status/v1", func(schema, _ string) bool { return schema == "console/status/v1" })
	read("console/snapshot/v1", func(schema, _ string) bool { return schema == "console/snapshot/v1" })
	// The console's viewport around the aircraft (console/subscribe/v1).
	const margin = 0.05
	sub := jsonBody(t, map[string]any{"schema": "console/subscribe/v1", "body": map[string]any{
		"bbox":   []float64{fx.Aircraft.LonDeg - margin, fx.Aircraft.LatDeg - margin, fx.Aircraft.LonDeg + margin, fx.Aircraft.LatDeg + margin},
		"layers": []string{"tracks", "alerts"}}})
	if err := c.Write(ctx, websocket.MessageText, sub); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	read("a frame of track "+trackID, func(_, f string) bool { return strings.Contains(f, trackID) })
	t.Logf("picture: frames %v; track %s arrived", seen, trackID)
	return trackID
}
