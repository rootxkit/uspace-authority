package manned

import (
	"math"
	"time"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/timeplace"
)

// sample is one track/manned/v1 envelope of a frame, decoded, before it
// is placed on this system's clock.
type sample struct {
	env  envelopeIn
	body Body
	// sourceAt is the sample's time on the ANSP's clock: captured_at, or
	// rx_ts when it carried no captured_at; zero when it carried neither.
	sourceAt time.Time
	// rxOK is false when the frame carried no usable rx_ts (T-12).
	rxOK bool
	ts   *time.Time
}

// placed is a sample on this system's clock.
type placed struct {
	sample
	rx         time.Time
	capturedAt time.Time
	timeSource core.TimeSource
	// orderAt is what orders the sample against the one held: sourceAt,
	// bounded by the arrival (Ingest.acceptLocked).
	orderAt time.Time
}

func parseStamp(p *string) (time.Time, bool) {
	if p == nil || *p == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, *p)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// newSample reads the times of one envelope.
func newSample(env envelopeIn, body Body) sample {
	s := sample{env: env, body: body}
	rx, rxOK := parseStamp(env.RxTS)
	s.rxOK = rxOK
	if at, ok := parseStamp(env.CapturedAt); ok {
		s.sourceAt = at
	} else if rxOK {
		s.sourceAt = rx
	}
	if ts, ok := parseStamp(env.TS); ok {
		s.ts = &ts
	}
	return s
}

// Placement counts (E-09).
type Placement struct {
	// AtArrival are the samples without a usable rx_ts, placed at
	// arrival (T-12).
	AtArrival int
	// Clamped are the spacings PlaceBatch clamped (T-02).
	Clamped int
	// WithoutAge are the batches whose ANSP write time was unknown (no
	// age_s on any of their samples): their newest sample is placed at
	// arrival, the ANSP's latency unseen.
	WithoutAge int
}

// placeBatch places the samples of one frame received at arrival on
// this system's clock (T-01, T-02). The batch's times are the samples'
// times on the ANSP's clock plus the ANSP's write time of the frame
// (each sample's captured_at + age_s; the latest of them): PlaceBatch
// then puts the write time at arrival and every sample before it by its
// age, so the ANSP's clock skew cancels within the frame and a 120 s
// spacing is the most a sample is placed before arrival (clamped and
// counted). A sample without a usable rx_ts is placed at arrival and
// counted (T-12), never dropped; one without ts keeps a null ts (it is
// not ordered within its source).
func placeBatch(samples []sample, arrival time.Time, maxSpacing time.Duration) ([]placed, Placement) {
	var count Placement
	out := make([]placed, len(samples))
	var times []time.Time
	var idx []int
	var write time.Time
	haveWrite := false
	for i := range samples {
		s := &samples[i]
		out[i] = placed{sample: *s, rx: arrival}
		if !s.rxOK || s.sourceAt.IsZero() {
			out[i].capturedAt, out[i].timeSource = arrival, core.TimeSystem
			if out[i].sourceAt.IsZero() {
				out[i].sourceAt = arrival
			}
			count.AtArrival++
			continue
		}
		times = append(times, s.sourceAt)
		idx = append(idx, i)
		if s.body.AgeS != nil && *s.body.AgeS >= 0 && !math.IsInf(*s.body.AgeS, 0) {
			w := s.sourceAt.Add(time.Duration(*s.body.AgeS * float64(time.Second)))
			if !haveWrite || w.After(write) {
				write, haveWrite = w, true
			}
		}
	}
	if len(times) == 0 {
		return out, count
	}
	if haveWrite {
		times = append(times, write)
	} else {
		count.WithoutAge++
	}
	at, clamped := timeplace.PlaceBatch(arrival, times, maxSpacing)
	count.Clamped = clamped
	for k, i := range idx {
		out[i].capturedAt, out[i].timeSource = at[k], core.TimeProvider
	}
	return out, count
}
