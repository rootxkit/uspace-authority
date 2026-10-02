package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/odid"

	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/ridpipe"
)

// transmitterPattern is a BT or Wi-Fi MAC address (rid/observation/v1).
var transmitterPattern = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$`)

// Observation is one validated observation of a batch.
type Observation struct {
	Transmitter      string
	Payload          []byte
	RSSIDBM          *float64
	RxTS             *time.Time
	ReceiverPosition *receivers.Position
}

// Batch is a validated rid/observation/v1 batch.
type Batch struct {
	ReceiverID   string
	SentAtMS     int64
	Nonce        string
	Backlog      bool
	Observations []Observation
}

type wireObservation struct {
	Transmitter      *string             `json:"transmitter"`
	PayloadHex       *string             `json:"payload_hex"`
	RSSIDBM          *float64            `json:"rssi_dbm"`
	RxTS             *string             `json:"rx_ts"`
	ReceiverPosition *receivers.Position `json:"receiver_position"`
}

type wireBatch struct {
	ReceiverID   string             `json:"receiver_id"`
	SentAtMS     int64              `json:"sent_at_ms"`
	Nonce        string             `json:"nonce"`
	Backlog      *bool              `json:"backlog"`
	Observations *[]json.RawMessage `json:"observations"`
}

// maxFieldErrors bounds the errors one batch reports (the problem caps at
// 100 anyway; collecting more is wasted work on a hostile body).
const maxFieldErrors = 100

// ParseBatch reads the signed report bytes core authenticated (never the
// unauthenticated body) as a rid/observation/v1 batch and validates every
// member, naming each failure by its JSON path. Unknown members are
// ignored within the major version (spec 02 §1). The caller has already
// bounded the bytes (MaxBatchBytes); nothing here panics on any input
// (FuzzParseBatch).
func ParseBatch(raw []byte) (Batch, error) {
	if len(raw) > receivers.MaxBatchBytes {
		return Batch{}, core.Fieldf("body", "longer than %d bytes", receivers.MaxBatchBytes)
	}
	var w wireBatch
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&w); err != nil {
		return Batch{}, core.Fieldf("body", "not a rid/observation/v1 batch: %v", trimErr(err))
	}
	var errs []error
	add := func(e error) {
		if len(errs) < maxFieldErrors {
			errs = append(errs, e)
		}
	}
	if !receivers.ValidID(w.ReceiverID) {
		add(core.Fieldf("receiver_id", "not a receiver id"))
	}
	if !validNonce(w.Nonce) {
		add(core.Fieldf("nonce", "1 to 256 bytes of UTF-8 without control characters"))
	}
	if w.Observations == nil {
		add(core.Fieldf("observations", "required"))
	} else if n := len(*w.Observations); n > receivers.MaxObservations {
		add(core.Fieldf("observations", "%d observations, at most %d", n, receivers.MaxObservations))
	}
	b := Batch{ReceiverID: w.ReceiverID, SentAtMS: w.SentAtMS, Nonce: w.Nonce, Backlog: w.Backlog != nil && *w.Backlog}
	if len(errs) > 0 {
		return Batch{}, errors.Join(errs...)
	}
	b.Observations = make([]Observation, 0, len(*w.Observations))
	for i, rawObs := range *w.Observations {
		path := "observations[" + strconv.Itoa(i) + "]"
		var o wireObservation
		if err := json.Unmarshal(rawObs, &o); err != nil {
			add(core.Fieldf(path, "not an observation: %v", trimErr(err)))
			continue
		}
		obs, oerrs := validateObservation(path, &o)
		for _, e := range oerrs {
			add(e)
		}
		if len(oerrs) == 0 {
			b.Observations = append(b.Observations, obs)
		}
	}
	if len(errs) > 0 {
		return Batch{}, errors.Join(errs...)
	}
	return b, nil
}

func validateObservation(path string, o *wireObservation) (Observation, []error) {
	var errs []error
	var out Observation
	switch {
	case o.Transmitter == nil:
		errs = append(errs, core.Fieldf(path+".transmitter", "required"))
	case !transmitterPattern.MatchString(*o.Transmitter):
		errs = append(errs, core.Fieldf(path+".transmitter", "not a MAC address (AA:BB:CC:DD:EE:FF)"))
	default:
		// One spelling per transmitter, so identity per transmitter
		// (I-01) never splits on letter case.
		out.Transmitter = strings.ToUpper(*o.Transmitter)
	}
	switch {
	case o.PayloadHex == nil:
		errs = append(errs, core.Fieldf(path+".payload_hex", "required"))
	case len(*o.PayloadHex) == 0 || len(*o.PayloadHex) > 2*receivers.MaxPayloadBytes || len(*o.PayloadHex)%2 != 0:
		errs = append(errs, core.Fieldf(path+".payload_hex", "1 to %d bytes as an even number of hex digits", receivers.MaxPayloadBytes))
	default:
		p, err := hex.DecodeString(*o.PayloadHex)
		if err != nil {
			errs = append(errs, core.Fieldf(path+".payload_hex", "not hex"))
		} else {
			out.Payload = p
		}
	}
	if o.RSSIDBM != nil {
		if v := *o.RSSIDBM; !core.IsFinite(v) || v < -200 || v > 50 {
			errs = append(errs, core.Fieldf(path+".rssi_dbm", "must be -200 to 50"))
		} else {
			out.RSSIDBM = o.RSSIDBM
		}
	}
	if o.RxTS != nil {
		t, err := parseRxTS(*o.RxTS)
		if err != nil {
			errs = append(errs, core.Fieldf(path+".rx_ts", "%v", err))
		} else {
			out.RxTS = &t
		}
	}
	if p := o.ReceiverPosition; p != nil {
		if !(core.LatLon{LatDeg: p.LatDeg, LonDeg: p.LonDeg}).Valid() {
			errs = append(errs, core.Fieldf(path+".receiver_position", "not a valid WGS84 position"))
		} else if a := p.AltHAEM; a != nil && (!core.IsFinite(*a) || *a < -1000 || *a > 10000) {
			errs = append(errs, core.Fieldf(path+".receiver_position.alt_hae_m", "must be -1000 to 10000"))
		} else {
			cp := *p
			out.ReceiverPosition = &cp
		}
	}
	return out, errs
}

// parseRxTS reads an RFC 3339 time in UTC ("Z"), the receiver's clock.
func parseRxTS(s string) (time.Time, error) {
	if len(s) > 40 || !strings.HasSuffix(s, "Z") {
		return time.Time{}, errors.New("must be RFC 3339 in UTC, ending in Z")
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, errors.New("must be RFC 3339 in UTC, ending in Z")
	}
	return t.UTC(), nil
}

func trimErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// FrameID is the id of one observation: hex of the first 16 bytes of
// SHA-256 over its dedupe key (receiver, transmitter, rx_ts, payload
// SHA-256, B-05). An observation without rx_ts has no dedupe key (two
// identical broadcasts a second apart are two frames, T-12), so the
// batch nonce and its index stand in and it is never merged.
func FrameID(receiverID, transmitter string, rxTS *time.Time, payloadSHA [32]byte, nonce string, index int) (id string, dedupable bool) {
	h := sha256.New()
	h.Write([]byte("rid-frame-v1\x00" + receiverID + "\x00" + transmitter + "\x00"))
	if rxTS != nil {
		h.Write([]byte(rxTS.UTC().Format(time.RFC3339Nano)))
		dedupable = true
	} else {
		h.Write([]byte("no-rx-ts\x00" + nonce + "\x00" + strconv.Itoa(index)))
	}
	h.Write([]byte{0})
	h.Write(payloadSHA[:])
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16]), dedupable
}

// Rows builds the raw rid_observations rows of b accepted at ingestTS.
// msg_type is the type nibble (uspace-core odid.TypeOf, for routing
// only; decoding is the Sink's).
func Rows(b *Batch, ingestTS time.Time) []ridpipe.Row {
	out := make([]ridpipe.Row, 0, len(b.Observations))
	for i := range b.Observations {
		o := &b.Observations[i]
		sum := sha256.Sum256(o.Payload)
		id, _ := FrameID(b.ReceiverID, o.Transmitter, o.RxTS, sum, b.Nonce, i)
		r := ridpipe.Row{
			IngestTS: ingestTS, FrameID: id, ReceiverID: b.ReceiverID, Transmitter: o.Transmitter, ReceiverTS: o.RxTS,
			Payload: o.Payload, PayloadSHA256: sum[:], RSSIDBM: o.RSSIDBM, Backlog: b.Backlog,
			SentAtMS: b.SentAtMS, Nonce: b.Nonce,
		}
		if t, err := odid.TypeOf(o.Payload); err == nil {
			v := int(t)
			r.MsgType = &v
		}
		if p := o.ReceiverPosition; p != nil {
			lat, lon := p.LatDeg, p.LonDeg
			r.ReceiverLatDeg, r.ReceiverLonDeg, r.ReceiverAltHAEM = &lat, &lon, p.AltHAEM
		}
		out = append(out, r)
	}
	return out
}

// validNonce admits what can be stored and logged safely: core already
// refused an empty or overlong nonce; a control character (NUL among
// them, which a text column refuses) is refused here.
func validNonce(n string) bool {
	if n == "" || len(n) > 256 || !utf8.ValidString(n) {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// BatchID is the id of a batch, unique per receiver within the nonce
// window: "<receiver_id>:<16 hex of SHA-256 of the nonce>", the JetStream
// message id of its queue and storage messages (a header value, so the
// nonce itself never goes there).
func BatchID(receiverID, nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return receiverID + ":" + hex.EncodeToString(sum[:8])
}
