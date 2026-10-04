package regportal

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/regnum"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/audit"
	"github.com/rootxkit/uspace-authority/internal/httpx"
	"github.com/rootxkit/uspace-authority/internal/registry"
)

func key(t testing.TB) []byte {
	t.Helper()
	k := make([]byte, KeyBytes)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func signer(t testing.TB) *Signer {
	t.Helper()
	s, err := NewSigner(key(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A token verifies under its key and purpose only; a tampered one, one
// of another purpose and one of another key do not.
func TestTokens(t *testing.T) {
	s := signer(t)
	c := Claims{Purpose: PurposeApplication, Subject: strings.Repeat("a", 32), Exp: time.Now().Add(time.Hour).Unix()}
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify(tok, PurposeApplication)
	if err != nil || got != c {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := s.Verify(tok, PurposeOperator); !errors.Is(err, ErrToken) {
		t.Fatal("verified for another purpose")
	}
	if _, err := signer(t).Verify(tok, PurposeApplication); !errors.Is(err, ErrToken) {
		t.Fatal("verified under another key")
	}
	parts := strings.Split(tok, ".")
	forged, _ := s.Sign(Claims{Purpose: PurposeApplication, Subject: strings.Repeat("b", 32), Exp: c.Exp})
	if _, err := s.Verify(parts[0]+"."+strings.Split(forged, ".")[1]+"."+parts[2], PurposeApplication); !errors.Is(err, ErrToken) {
		t.Fatal("a payload under another signature verified")
	}
	for _, bad := range []string{"", "v2." + parts[1] + "." + parts[2], tok + ".", strings.Repeat("x", MaxTokenBytes+1)} {
		if _, err := s.Verify(bad, PurposeApplication); !errors.Is(err, ErrToken) {
			t.Errorf("%q verified", bad)
		}
	}
	if s.Hash("ip", "192.0.2.1") == s.Hash("ip", "192.0.2.2") || s.Hash("ip", "x") == s.Hash("operator", "x") || len(s.Hash("ip", "x")) != 64 {
		t.Fatal("hash")
	}
	if _, err := NewSigner(make([]byte, 16)); err == nil {
		t.Fatal("a short key")
	}
}

func FuzzVerifyToken(f *testing.F) {
	s := signer(f)
	tok, _ := s.Sign(Claims{Purpose: PurposeOperator, Subject: "op", Link: "l", Number: "n", Exp: 1})
	f.Add(tok)
	f.Add("v1..")
	f.Add("v1.e30.")
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := s.Verify(tok, PurposeOperator)
		if err == nil && (c.Purpose != PurposeOperator || c.Subject == "" || c.Exp <= 0) {
			t.Fatalf("verified %+v", c)
		}
	})
}

// numbers is a registry for IssueNumber: the default pattern, a set of
// taken compare keys.
type numbers struct {
	pattern string
	taken   map[string]bool
	asked   int
}

func (n *numbers) NumberFree(_ context.Context, number string) (string, bool, error) {
	n.asked++
	v, err := regnum.NewValidator(n.pattern)
	if err != nil {
		return "", false, err
	}
	if err := v.Validate(number); err != nil {
		return "", false, err
	}
	p, k := v.Public(number)
	return p, !n.taken[k], nil
}

func (n *numbers) CheckNumber(context.Context, string) (registry.PublicCheck, error) {
	return registry.PublicCheck{}, nil
}

func (n *numbers) CreateOperator(context.Context, registry.NewOperator, audit.Actor) (registry.Operator, error) {
	return registry.Operator{}, nil
}

func (n *numbers) OperatorBySource(context.Context, string, string) (registry.Operator, bool, error) {
	return registry.Operator{}, false, nil
}

func (n *numbers) ContactForLink(context.Context, string) (registry.OperatorContact, bool, error) {
	return registry.OperatorContact{}, false, nil
}

// Issued numbers follow the policy's pattern and never repeat; a taken
// one is drawn again; a shape the pattern refuses is a 409 at once.
func TestIssueNumber(t *testing.T) {
	reg := &numbers{pattern: regnum.DefaultPattern, taken: map[string]bool{}}
	shape := regexp.MustCompile(`^GEO[0-9a-z]{12}$`)
	v, _ := regnum.NewValidator(regnum.DefaultPattern)
	for range 2000 {
		n, err := IssueNumber(context.Background(), reg, "GEO", 12, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !shape.MatchString(n) || v.Validate(n) != nil {
			t.Fatalf("%q", n)
		}
		k := v.CompareKey(n)
		if reg.taken[k] {
			t.Fatalf("%q issued twice", n)
		}
		reg.taken[k] = true
	}
	// Every draw taken: a bounded number of draws, then an error.
	full := &numbers{pattern: `^GEO[0-9a-z]$`, taken: map[string]bool{}}
	for _, c := range issueAlphabet {
		full.taken["GEO"+strings.ToUpper(string(c))] = true
	}
	collisions := 0
	if _, err := IssueNumber(context.Background(), full, "GEO", 1, func() { collisions++ }); err == nil || full.asked != maxIssueAttempts || collisions != maxIssueAttempts {
		t.Fatalf("err %v asked %d collisions %d", err, full.asked, collisions)
	}
	// A shape the pattern refuses: 409, one draw.
	narrow := &numbers{pattern: `^GEO[0-9]{12}$`, taken: map[string]bool{}}
	_, err := IssueNumber(context.Background(), narrow, "XX", 12, nil)
	if p := httpx.ProblemFromError(err); p.Status != http.StatusConflict || p.Slug() != SlugIssuance || narrow.asked != 1 {
		t.Fatalf("%v asked %d", err, narrow.asked)
	}
	s, err := SecretPart()
	if err != nil || len(s) != 3 || !regexp.MustCompile(`^[0-9a-z]{3}$`).MatchString(s) {
		t.Fatalf("%q %v", s, err)
	}
}

var placeholder = regexp.MustCompile(`\{[a-z_]+\}`)

// The ka and en catalogues hold the same e-mails with the same
// placeholders (CLAUDE.md rule 12).
func TestCataloguesMatch(t *testing.T) {
	c, err := LoadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{MailVerify, MailApproved, MailRefused, MailLink} {
		en, ka := c["en"][kind], c["ka"][kind]
		if en.Subject == "" || ka.Subject == "" || en.Body == "" || ka.Body == "" {
			t.Fatalf("%s missing", kind)
		}
		pe, pk := placeholder.FindAllString(en.Body, -1), placeholder.FindAllString(ka.Body, -1)
		if fmt.Sprint(uniq(pe)) != fmt.Sprint(uniq(pk)) {
			t.Errorf("%s placeholders en %v ka %v", kind, uniq(pe), uniq(pk))
		}
	}
	if len(c["en"]) != 4 || len(c["ka"]) != 4 {
		t.Fatalf("catalogues %d %d", len(c["en"]), len(c["ka"]))
	}
	_, body, err := c.Render(MailApproved, "ka", Message{Vars: map[string]string{"number": "GEOx", "secret": "abc", "valid_until": "u", "link": "l"}})
	if err != nil || placeholder.MatchString(body) || !strings.Contains(body, "GEOx-abc") {
		t.Fatalf("%v %q", err, body)
	}
	if _, _, err := c.Render("unknown", "en", Message{}); err == nil {
		t.Fatal("rendered an unknown kind")
	}
}

func uniq(s []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// A value of the message never reaches a header; the subject is encoded.
func TestComposeKeepsValuesOutOfHeaders(t *testing.T) {
	msg := string(Compose("portal@example.test", "a@example.test", "ტესტი", "line\nBcc: x@example.test", time.Unix(0, 0)))
	head, body, _ := strings.Cut(msg, "\r\n\r\n")
	if strings.Contains(head, "Bcc") || !strings.Contains(head, "Subject: =?utf-8?b?") {
		t.Fatalf("head %q", head)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(body, "\r\n", ""))
	if err != nil || !strings.Contains(string(dec), "Bcc: x@example.test") {
		t.Fatalf("body %q %v", dec, err)
	}
}

func TestCheckSMTP(t *testing.T) {
	good := SMTP{Addr: "127.0.0.1:2525", From: "portal@example.test", TLS: "none"}
	if err := CheckSMTP(good); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]SMTP{
		"clear over a network": {Addr: "relay.example.test:25", From: good.From, TLS: "none"},
		"no port":              {Addr: "relay.example.test", From: good.From, TLS: "starttls"},
		"bad from":             {Addr: good.Addr, From: "Portal <portal@example.test>", TLS: "none"},
	} {
		if err := CheckSMTP(m); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// fakeSMTP is a loopback SMTP relay that keeps what it is sent, or
// refuses every recipient with code.
type fakeSMTP struct {
	mu       sync.Mutex
	got      []string
	tls      bool
	rcptCode int
	l        net.Listener
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{l: l}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) addr() string { return f.l.Addr().String() }

func (f *fakeSMTP) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	say := func(s string) { _, _ = io.WriteString(c, s+"\r\n") }
	say("220 fake")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if f.tls {
				say("250-fake")
				say("250 STARTTLS")
			} else {
				say("250 fake")
			}
		case strings.HasPrefix(cmd, "MAIL"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT"):
			f.mu.Lock()
			code := f.rcptCode
			f.mu.Unlock()
			if code != 0 {
				say(fmt.Sprintf("%d refused", code))
				continue
			}
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.got = append(f.got, b.String())
			f.mu.Unlock()
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

// The mailer delivers through a loopback relay, refuses a relay without
// STARTTLS when it is required, and marks a 5xx refusal permanent and a
// 4xx one not.
func TestSMTPMailer(t *testing.T) {
	relay := newFakeSMTP(t)
	m := SMTP{Addr: relay.addr(), From: "portal@example.test", TLS: "none", Timeout: 5 * time.Second}
	if err := m.Send(context.Background(), "a@example.test", "Subject", "Hello"); err != nil {
		t.Fatal(err)
	}
	if got := relay.messages(); len(got) != 1 || !strings.Contains(got[0], "To: a@example.test") {
		t.Fatalf("%q", got)
	}
	m.TLS = "starttls"
	if err := m.Send(context.Background(), "a@example.test", "Subject", "Hello"); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("sent in clear: %v", err)
	}
	m.TLS = "none"
	relay.rcptCode = 550
	var perm *PermanentError
	if err := m.Send(context.Background(), "a@example.test", "S", "B"); !errors.As(err, &perm) {
		t.Fatalf("550 not permanent: %v", err)
	}
	relay.rcptCode = 451
	if err := m.Send(context.Background(), "a@example.test", "S", "B"); err == nil || errors.As(err, &perm) {
		t.Fatalf("451 permanent: %v", err)
	}
}

func TestRetryIn(t *testing.T) {
	if retryIn(time.Minute, 1) != time.Minute || retryIn(time.Minute, 3) != 4*time.Minute || retryIn(time.Minute, 30) != maxRetry {
		t.Fatal(retryIn(time.Minute, 3))
	}
	if got := lastError(errors.New(strings.Repeat("ტ", 200))); len(got) > 300 || !strings.HasPrefix(got, "ტ") {
		t.Fatalf("%d", len(got))
	}
}

// E-01 for the flags: with a flag off, every operation it gates is 404
// and touches nothing (the service has no database here); the
// integration tests run the same operations with the flags on.
func TestFlagsOffAnswerNotFound(t *testing.T) {
	h := Handler{Service: &Service{Counters: &core.Counters{}}, Check: &numbers{}}
	ctx := apiserver.WithIdentity(context.Background(), apiserver.Identity{ActorType: "user", Subject: "registrar-1", Session: true, Realm: "console"})
	id := strings.Repeat("a", 32)
	calls := map[string]func() error{
		"submit": func() error {
			_, err := h.SubmitRegistryApplication(ctx, gen.SubmitRegistryApplicationRequestObject{Body: &gen.SubmitRegistryApplicationJSONRequestBody{}})
			return err
		},
		"status": func() error {
			_, err := h.GetRegistryApplicationStatus(ctx, gen.GetRegistryApplicationStatusRequestObject{ApplicationId: id})
			return err
		},
		"verify": func() error {
			_, err := h.VerifyRegistryApplication(ctx, gen.VerifyRegistryApplicationRequestObject{ApplicationId: id})
			return err
		},
		"list": func() error {
			_, err := h.ListRegistryApplications(ctx, gen.ListRegistryApplicationsRequestObject{})
			return err
		},
		"personal data": func() error {
			_, err := h.GetRegistryApplicationPersonalData(ctx, gen.GetRegistryApplicationPersonalDataRequestObject{ApplicationId: id, Params: gen.GetRegistryApplicationPersonalDataParams{Purpose: "x"}})
			return err
		},
		"review": func() error {
			_, err := h.StartRegistryApplicationReview(ctx, gen.StartRegistryApplicationReviewRequestObject{ApplicationId: id})
			return err
		},
		"approve": func() error {
			_, err := h.ApproveRegistryApplication(ctx, gen.ApproveRegistryApplicationRequestObject{ApplicationId: id})
			return err
		},
		"refuse": func() error {
			_, err := h.RefuseRegistryApplication(ctx, gen.RefuseRegistryApplicationRequestObject{ApplicationId: id, Body: &gen.RefuseRegistryApplicationJSONRequestBody{Reason: "x"}})
			return err
		},
		"link": func() error {
			_, err := h.RequestOperatorLink(ctx, gen.RequestOperatorLinkRequestObject{Body: &gen.RequestOperatorLinkJSONRequestBody{RegistrationNumber: "GEOTEST00000001"}})
			return err
		},
		"report": func() error {
			_, err := h.CreateOperatorOccurrence(ctx, gen.CreateOperatorOccurrenceRequestObject{})
			return err
		},
	}
	for name, call := range calls {
		if p := httpx.ProblemFromError(call()); p.Status != http.StatusNotFound {
			t.Errorf("%s: %d %s", name, p.Status, p.Detail)
		}
	}
	if n := h.Service.Counters.Get(CounterOff); n != uint64(len(calls)) {
		t.Fatalf("counted %d of %d", n, len(calls))
	}
}

// The public check answers status and validity only, and its limiter
// refuses past the address's budget (E-10: the limiter's bound is
// httpx's, exceeded in its own tests).
func TestCheckRegistrationIsStatusOnlyAndLimited(t *testing.T) {
	until := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	h := Handler{Service: &Service{Counters: &core.Counters{}}, Check: checkStub{registry.PublicCheck{Status: registry.ValidityValid, ValidUntil: &until}},
		CheckLimit: httpx.NewRateLimiter(1.0/60, 2, 10, nil)}
	ctx := apiserver.WithRequestInfo(context.Background(), apiserver.RequestInfo{RemoteIP: "192.0.2.7"})
	req := gen.CheckRegistrationRequestObject{Params: gen.CheckRegistrationParams{Number: "GEOTEST00000001"}}
	for range 2 {
		resp, err := h.CheckRegistration(ctx, req)
		ok, isOK := resp.(gen.CheckRegistration200JSONResponse)
		if err != nil || !isOK || ok.Status != "valid" || !ok.ValidUntil.Equal(until) {
			t.Fatalf("%+v %v", resp, err)
		}
	}
	resp, err := h.CheckRegistration(ctx, req)
	if _, limited := resp.(gen.CheckRegistration429ApplicationProblemPlusJSONResponse); err != nil || !limited || h.Service.Counters.Get(CounterCheckLimited) != 1 {
		t.Fatalf("%+v %v", resp, err)
	}
	// Another address has its own budget.
	other := apiserver.WithRequestInfo(context.Background(), apiserver.RequestInfo{RemoteIP: "192.0.2.8"})
	if resp, err := h.CheckRegistration(other, req); err != nil {
		t.Fatal(err)
	} else if _, isOK := resp.(gen.CheckRegistration200JSONResponse); !isOK {
		t.Fatalf("%+v", resp)
	}
}

type checkStub struct{ c registry.PublicCheck }

func (s checkStub) CheckNumber(context.Context, string) (registry.PublicCheck, error) {
	return s.c, nil
}

func TestCursor(t *testing.T) {
	at := time.Date(2026, 10, 4, 1, 2, 3, 456, time.UTC)
	id := strings.Repeat("f", 32)
	a, b, err := DecodeCursor(EncodeCursor(at, id))
	if err != nil || !a.Equal(at) || b != id {
		t.Fatalf("%v %v %v", a, b, err)
	}
	for _, bad := range []string{"", "!!", base64.RawURLEncoding.EncodeToString([]byte("x|y"))} {
		if _, _, err := DecodeCursor(bad); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
}
