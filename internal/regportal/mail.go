package regportal

import (
	"bytes"
	"context"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"slices"
	"strings"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

// Mail kinds: the portal's e-mails (registry_portal_mail.kind).
const (
	MailVerify   = "verify_application"
	MailApproved = "application_approved"
	MailRefused  = "application_refused"
	MailLink     = "operator_link"
)

// Languages of the portal's e-mails (CLAUDE.md rule 12).
var Languages = []string{"en", "ka"}

//go:embed catalogue/*.json
var catalogueFS embed.FS

// Template is one e-mail of the catalogue: {name} placeholders are
// replaced by the message's values.
type Template struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// Catalogue is every e-mail in every language.
type Catalogue map[string]map[string]Template

// LoadCatalogue reads the embedded catalogues (catalogue/<lang>.json).
func LoadCatalogue() (Catalogue, error) {
	out := Catalogue{}
	for _, lang := range Languages {
		raw, err := catalogueFS.ReadFile("catalogue/" + lang + ".json")
		if err != nil {
			return nil, err
		}
		var m map[string]Template
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("catalogue %s: %w", lang, err)
		}
		out[lang] = m
	}
	return out, nil
}

// Message is one queued e-mail's content as sealed in the outbox: the
// recipient and the values of its template.
type Message struct {
	To   string            `json:"to"`
	Vars map[string]string `json:"vars"`
}

// Render fills the template of kind in lang with m's values. A value
// never reaches a header: the subject is the catalogue's alone.
func (c Catalogue) Render(kind, lang string, m Message) (subject, body string, err error) {
	t, ok := c[lang][kind]
	if !ok {
		return "", "", fmt.Errorf("no %s template in %s", kind, lang)
	}
	body = t.Body
	for k, v := range m.Vars {
		body = strings.ReplaceAll(body, "{"+k+"}", v)
	}
	return t.Subject, body, nil
}

// Mailer delivers one e-mail.
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// PermanentError is a refusal the relay will repeat (SMTP 5xx): the
// message is failed at once, never retried (a permanent answer is
// permanent).
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return "permanent: " + e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// SMTP is Mailer over an SMTP relay. TLS is "starttls" (required: a
// relay that does not offer it is refused, never used in clear), "tls"
// (implicit TLS) or "none" (a loopback relay only).
type SMTP struct {
	Addr     string
	From     string
	User     string
	Password string
	TLS      string
	Timeout  time.Duration
}

// CheckSMTP refuses a configuration that would send in clear over a
// network or with a malformed address.
func CheckSMTP(m SMTP) error {
	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil || host == "" {
		return core.Fieldf("REGISTRY_MAIL_SMTP_ADDR", "must be host:port")
	}
	if a, err := mail.ParseAddress(m.From); err != nil || a.Name != "" || a.Address != m.From {
		return core.Fieldf("REGISTRY_MAIL_FROM", "not an e-mail address")
	}
	if m.TLS == "none" {
		if ip := net.ParseIP(host); (ip == nil || !ip.IsLoopback()) && host != "localhost" {
			return core.Fieldf("REGISTRY_MAIL_TLS", "none is allowed only to a loopback relay")
		}
	}
	return nil
}

// Send implements Mailer.
func (m SMTP) Send(ctx context.Context, to, subject, body string) error {
	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(m.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	d := net.Dialer{Deadline: deadline}
	var conn net.Conn
	tlsConf := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if m.TLS == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", m.Addr, tlsConf)
	} else {
		conn, err = d.DialContext(ctx, "tcp", m.Addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(deadline)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return classify(err)
	}
	defer func() { _ = c.Close() }()
	if m.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("the relay offers no STARTTLS; nothing is sent in clear")
		}
		if err := c.StartTLS(tlsConf); err != nil {
			return classify(err)
		}
	}
	if m.User != "" {
		if err := c.Auth(smtp.PlainAuth("", m.User, m.Password, host)); err != nil {
			return classify(err)
		}
	}
	if err := c.Mail(m.From); err != nil {
		return classify(err)
	}
	if err := c.Rcpt(to); err != nil {
		return classify(err)
	}
	w, err := c.Data()
	if err != nil {
		return classify(err)
	}
	if _, err := w.Write(Compose(m.From, to, subject, body, time.Now())); err != nil {
		return classify(err)
	}
	if err := w.Close(); err != nil {
		return classify(err)
	}
	return classify(c.Quit())
}

// classify marks an SMTP 5xx refusal permanent.
func classify(err error) error {
	var te *textproto.Error
	if errors.As(err, &te) && te.Code >= 500 {
		return &PermanentError{Err: err}
	}
	return err
}

// Compose is the RFC 5322 message: UTF-8 text in base64, the subject
// RFC 2047 encoded, no value of the message in a header but the
// recipient (checked as an address at intake).
func Compose(from, to, subject, body string, at time.Time) []byte {
	var b bytes.Buffer
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", to)
	h("Subject", mime.BEncoding.Encode("utf-8", subject))
	h("Date", at.UTC().Format(time.RFC1123Z))
	h("MIME-Version", "1.0")
	h("Content-Type", "text/plain; charset=utf-8")
	h("Content-Transfer-Encoding", "base64")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.ReplaceAll(body, "\n", "\r\n")))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return b.Bytes()
}

// validLang reports a catalogue language.
func validLang(l string) bool { return slices.Contains(Languages, l) }
