package archive

import (
	"bytes"
	"errors"
	"reflect"

	"github.com/rootxkit/uspace-core/odid"
)

// SystemTypes are the ODID message types whose frame may carry the
// remote pilot position: a System message, or a message pack that may
// hold one (uspace-core odid; spec 06 §5).
var SystemTypes = []int{int(odid.TypeSystem), int(odid.TypeMessagePack)}

// Redaction is what RedactOperator did to a frame.
type Redaction int

// The outcomes of RedactOperator.
const (
	// Unchanged: the frame carries no remote pilot position.
	Unchanged Redaction = iota
	// Redacted: the System message's operator position (latitude,
	// longitude and geodetic altitude) is now the "unknown" value; every
	// other byte of the frame is as received.
	Redacted
	// Undecodable: the frame could not be decoded (or the redaction
	// could not be checked), so the position cannot be removed from it
	// alone; the caller leaves the payload out of the archive.
	Undecodable
)

// RedactOperator removes the remote pilot position from an ODID frame
// (a single message or a message pack). Only the 25 bytes of the System
// message are re-encoded, through uspace-core's codec, with the
// operator position unknown; the result is decoded again and must
// equal the original's decoding with that position cleared, or the
// frame is reported Undecodable (never a guess, LESSONS E-03).
func RedactOperator(frame []byte) ([]byte, Redaction) {
	opts := odid.DecodeOptions{KeepSkipped: true}
	before, err := odid.Decode(frame, opts)
	if err != nil {
		return nil, Undecodable
	}
	carries := false
	for _, m := range before {
		if s, ok := m.(odid.System); ok && (s.OperatorLatDeg != nil || s.OperatorLonDeg != nil || s.OperatorAltHAEM != nil) {
			carries = true
		}
	}
	if !carries {
		return frame, Unchanged
	}
	out := bytes.Clone(frame)
	t, err := odid.TypeOf(frame)
	if err != nil {
		return nil, Undecodable
	}
	var slots []int // the offsets of the messages of the frame
	if t == odid.TypeMessagePack {
		for i := range before {
			slots = append(slots, odid.PackHeaderSize+i*odid.MessageSize)
		}
	} else {
		slots = []int{0}
	}
	for _, off := range slots {
		if off+odid.MessageSize > len(out) {
			return nil, Undecodable
		}
		msg := [odid.MessageSize]byte(out[off : off+odid.MessageSize])
		if mt, err := odid.TypeOf(msg[:]); err != nil || mt != odid.TypeSystem {
			continue
		}
		m, err := odid.DecodeMessage(msg, opts)
		if err != nil {
			return nil, Undecodable
		}
		s, ok := m.(odid.System)
		if !ok {
			return nil, Undecodable
		}
		s.OperatorLatDeg, s.OperatorLonDeg, s.OperatorAltHAEM = nil, nil, nil
		enc, err := odid.Encode(s)
		if err != nil {
			return nil, Undecodable
		}
		copy(out[off:], enc[:])
	}
	if err := checkRedaction(before, out, opts); err != nil {
		return nil, Undecodable
	}
	return out, Redacted
}

// checkRedaction decodes the redacted frame and compares it with the
// original decoding with the operator position cleared.
func checkRedaction(before []odid.Message, redacted []byte, opts odid.DecodeOptions) error {
	after, err := odid.Decode(redacted, opts)
	if err != nil {
		return err
	}
	want := make([]odid.Message, len(before))
	for i, m := range before {
		if s, ok := m.(odid.System); ok {
			s.OperatorLatDeg, s.OperatorLonDeg, s.OperatorAltHAEM = nil, nil, nil
			m = s
		}
		want[i] = m
	}
	if !reflect.DeepEqual(want, after) {
		return errors.New("archive: the redacted frame does not decode as the original without the operator position")
	}
	for _, m := range after {
		if s, ok := m.(odid.System); ok && (s.OperatorLatDeg != nil || s.OperatorLonDeg != nil || s.OperatorAltHAEM != nil) {
			return errors.New("archive: the redacted frame still carries an operator position")
		}
	}
	return nil
}
