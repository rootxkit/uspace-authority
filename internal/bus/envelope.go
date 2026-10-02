package bus

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Envelope is the 04 §2 envelope with its body, the shape of every
// message on a subject that carries a 04 message (M29).
type Envelope[B any] struct {
	Schema     string `json:"schema"`
	MsgID      string `json:"msg_id"`
	Producer   string `json:"producer"`
	TS         string `json:"ts"`
	RxTS       string `json:"rx_ts"`
	CapturedAt string `json:"captured_at"`
	TimeSource string `json:"time_source"`
	Backlog    bool   `json:"backlog"`
	Body       B      `json:"body"`
}

// Stamp is the envelope's timestamp form: RFC 3339 UTC with
// milliseconds and Z (02 §1).
func Stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// SystemEnvelope wraps body produced by this system at now: ts, rx_ts
// and captured_at are all now on this system's clock, time_source
// "system", never backlog.
func SystemEnvelope[B any](schema, producer string, now time.Time, body B) Envelope[B] {
	s := Stamp(now)
	return Envelope[B]{
		Schema: schema, MsgID: NewULID(now), Producer: producer,
		TS: s, RxTS: s, CapturedAt: s, TimeSource: "system", Body: body,
	}
}

// Publisher sends one core NATS message (*nats.Conn).
type Publisher interface {
	Publish(subject string, data []byte) error
}

// PublishCore sends env on subject over core NATS (no acknowledgement:
// status and push subjects).
func PublishCore[B any](p Publisher, subject string, env Envelope[B]) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return p.Publish(subject, data)
}

// PublishJS writes env to the stream that holds subject and returns once
// JetStream acknowledged it. The message id is msg_id, so a retried
// write inside the duplicate window is stored once.
func PublishJS[B any](ctx context.Context, js jetstream.JetStream, subject string, env Envelope[B]) (*jetstream.PubAck, error) {
	data, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	msg := nats.NewMsg(subject)
	msg.Data = data
	msg.Header.Set(jetstream.MsgIDHeader, env.MsgID)
	ack, err := js.PublishMsg(ctx, msg)
	if err != nil {
		return nil, fmt.Errorf("publish %s: %w", subject, err)
	}
	return ack, nil
}

// crockford is the ULID alphabet.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewULID returns a ULID for at: 48 bits of milliseconds and 80 random
// bits, Crockford base32 (the envelope's msg_id).
func NewULID(at time.Time) string {
	var b [16]byte
	ms := uint64(at.UnixMilli()) & (1<<48 - 1)
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	// 128 bits as 26 base32 digits, least significant first: the top
	// digit holds the top 3 bits, so it is 0-7 as the schema requires.
	var out [26]byte
	hi := uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])
	lo := uint64(b[8])<<56 | uint64(b[9])<<48 | uint64(b[10])<<40 | uint64(b[11])<<32 | uint64(b[12])<<24 | uint64(b[13])<<16 | uint64(b[14])<<8 | uint64(b[15])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | (hi&31)<<59
		hi >>= 5
	}
	return string(out[:])
}
