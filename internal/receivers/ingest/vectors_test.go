package ingest

import (
	"bytes"
	"encoding/hex"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/vectors"

	"github.com/rootxkit/uspace-authority/internal/receivers"
)

type vecSignInput struct {
	KeyHex     string `json:"key_hex"`
	ReportUTF8 string `json:"report_utf8"`
}

type vecSignExpected struct {
	DatagramUTF8 string `json:"datagram_utf8"`
	SignatureHex string `json:"signature_hex"`
}

type vecVerifyInput struct {
	KeysHex   map[string]string `json:"keys_hex"`
	MaxSkewS  float64           `json:"max_skew_s"`
	Datagrams []struct {
		UTF8 string  `json:"utf8"`
		NowS float64 `json:"now_s"`
	} `json:"datagrams"`
}

type vecVerifyExpected struct {
	PerDatagram []struct {
		Accepted bool    `json:"accepted"`
		Error    *string `json:"error"`
	} `json:"per_datagram"`
}

func epochSeconds(s float64) time.Time {
	sec, frac := math.Modf(s)
	return time.Unix(int64(sec), int64(math.Round(frac*1e9))).UTC()
}

// splitDatagram is the receiver's side of the HTTP mapping: a vector
// datagram "<report>\nsig=<hex>" is the body (the exact signed bytes) and
// the X-Report-Signature header; a datagram without the marker is an
// unsigned body.
func splitDatagram(d []byte) (body []byte, sig string) {
	i := bytes.LastIndex(d, []byte(auth.SignatureMarker))
	if i < 0 {
		return d, ""
	}
	return d[:i], string(d[i+len(auth.SignatureMarker):])
}

// rid_receiver_auth.json through the authority's HTTP adapter: each vector
// datagram is sent as body + X-Report-Signature to POST
// /v1/rid/observations with the bearer key of a receiver holding the
// vector's HMAC key, and the handler reassembles the datagram core
// verifies. This proves the mapping, not core: a refused vector is
// refused over HTTP with core's own phrase as the detail and its status
// (401 signature or skew, 409 replay, 400 malformed); an accepted vector
// passes authentication. The vectors' reports are the predecessor's
// single-observation datagrams, not rid/observation/v1 batches, so an
// accepted one then meets the batch validation (400 validation naming
// `observations`), which the test asserts by name: it is authenticated,
// and nothing else in it is.
func TestVectorsRIDReceiverAuthThroughTheHTTPAdapter(t *testing.T) {
	f := vectors.Load(t, "rid_receiver_auth.json")
	h := cheapHasher(t)
	f.RunOwned(t, "authority", func(t *testing.T, c vectors.Case) {
		if c.Name == "signature-is-hmac-sha256-hex-of-report-bytes" {
			var in vecSignInput
			var exp vecSignExpected
			c.Decode(t, &in, &exp)
			key, err := hex.DecodeString(in.KeyHex)
			if err != nil {
				t.Fatal(err)
			}
			// The receiver signs the body bytes alone; the header carries
			// the hex; the adapter's datagram is core's.
			sig := auth.SignReport(key, []byte(in.ReportUTF8))
			if sig != exp.SignatureHex {
				t.Fatalf("signature %s, want %s", sig, exp.SignatureHex)
			}
			if got := string(receivers.Datagram([]byte(in.ReportUTF8), sig)); got != exp.DatagramUTF8 {
				t.Fatalf("datagram %q, want %q", got, exp.DatagramUTF8)
			}
			return
		}
		var in vecVerifyInput
		var exp vecVerifyExpected
		c.Decode(t, &in, &exp)
		if time.Duration(in.MaxSkewS*float64(time.Second)) != receivers.MaxSkew {
			t.Fatalf("the vector's window %v s is not the ingest's %v", in.MaxSkewS, receivers.MaxSkew)
		}
		var rxs []rx
		for id, kh := range in.KeysHex {
			key, err := hex.DecodeString(kh)
			if err != nil {
				t.Fatal(err)
			}
			rxs = append(rxs, newRx(t, h, id, key))
		}
		fx := newFixture(t, rxs...)
		bearer := rxs[0].bearer
		for i, d := range in.Datagrams {
			want := exp.PerDatagram[i]
			fx.now = epochSeconds(d.NowS)
			body, sig := splitDatagram([]byte(d.UTF8))
			rec := fx.post(t, bearer, string(body), sig)
			p := problemOf(t, rec.Body.String())
			if want.Accepted {
				if rec.Code != http.StatusBadRequest || p.Slug() != receivers.SlugValidation ||
					len(p.Errors) == 0 || p.Errors[0].Field != "observations" {
					t.Fatalf("datagram %d: authenticated vector answered %d %s %+v", i, rec.Code, p.Slug(), p.Errors)
				}
				continue
			}
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusConflict && rec.Code != http.StatusBadRequest {
				t.Fatalf("datagram %d: refused vector answered %d", i, rec.Code)
			}
			if want.Error != nil && p.Detail != *want.Error {
				t.Fatalf("datagram %d: detail %q, want core's phrase %q", i, p.Detail, *want.Error)
			}
			if p.Slug() == receivers.SlugValidation && len(p.Errors) > 0 && p.Errors[0].Field == "observations" {
				t.Fatalf("datagram %d: a refused vector passed authentication", i)
			}
		}
	})
}
