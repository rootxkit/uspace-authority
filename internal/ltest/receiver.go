package ltest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"sync"
	"time"

	"github.com/rootxkit/uspace-core/auth"
	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geoid"
	"github.com/rootxkit/uspace-core/odid"
	"github.com/rootxkit/uspace-core/rid"

	"github.com/rootxkit/uspace-authority/api/gen"
	"github.com/rootxkit/uspace-authority/internal/passhash"
	"github.com/rootxkit/uspace-authority/internal/receivers"
)

// State is where an aircraft is at one step of its path, with the
// broadcast changes of that step.
type State struct {
	LatDeg, LonDeg float64
	// AltAMSLM is the aircraft's altitude above mean sea level; the
	// transmitter broadcasts AltAMSLM + N as its geodetic (HAE)
	// altitude, N from the test geoid the ingest also reads (R-16).
	AltAMSLM float64
	SpeedMS  float64
	TrackDeg float64
	// Status is the ODID operational status (StatusGround is the only
	// "not airborne"); the zero value, undeclared, counts as airborne.
	Status odid.Status
	// Silent transmits nothing this step.
	Silent bool
	// Serial, OperatorID and Transmitter, when set, replace the
	// aircraft's own from this step (a module restarted with a new
	// serial, a corrected operator number, an address change: SC-06,
	// SC-10).
	Serial, OperatorID, Transmitter *string
}

// Path is an aircraft's state at each step (0, 1, 2, ...).
type Path func(step int) State

// Hold is a path that stays at one point, airborne.
func Hold(latDeg, lonDeg, altAMSLM float64) Path {
	return func(int) State {
		return State{LatDeg: latDeg, LonDeg: lonDeg, AltAMSLM: altAMSLM, Status: odid.StatusAirborne}
	}
}

// Aircraft is one simulated Remote ID transmitter.
type Aircraft struct {
	// Transmitter is its Bluetooth or Wi-Fi address (upper case, as
	// the ingest normalises it).
	Transmitter string
	// Serial is the ANSI/CTA-2063-A serial of its Basic ID; empty
	// broadcasts no Basic ID.
	Serial string
	// OperatorID is its Operator ID message; empty sends none.
	OperatorID string
	// System adds the System message (operator position at the
	// receiver, EU classification).
	System bool
	// OnePerDatagram sends each message as its own observation
	// (Bluetooth 4) instead of one message pack; the Basic ID, System
	// and Operator ID then go every BasicIDEvery steps (1 when 0).
	OnePerDatagram bool
	BasicIDEvery   int
	// UTCFromStep is the first step at which the transmitter knows UTC;
	// before it the Location carries no timestamp (R-16).
	UTCFromStep int
	Path        Path
}

// TrackID is the track id the ingest gives the aircraft: its serial's
// (rid.AircraftID), or its address's when it broadcasts no serial.
func (a *Aircraft) TrackID() string {
	if a.Serial != "" {
		return rid.AircraftID(odid.IDTypeSerial, a.Serial)
	}
	return rid.UnidentifiedID(a.Transmitter)
}

// SerialTrackID is the track id of a serial.
func SerialTrackID(serial string) string { return rid.AircraftID(odid.IDTypeSerial, serial) }

// Tally is a receiver's no-silent-loss account, in observations:
// Sent = Accepted + Duplicates + Refused + Dropped + Failed.
type Tally struct {
	// Sent is every observation the simulator built.
	Sent int `json:"sent"`
	// Accepted and Duplicates are what the ingest's 202 said.
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	// Refused are the observations of refused batches, by status and
	// problem slug.
	Refused      int            `json:"refused"`
	RefusedBy    map[string]int `json:"refused_by"`
	RefusedBatch int            `json:"refused_batches"`
	// Dropped are lost on the simulated radio link (drop rate, Drop).
	Dropped int `json:"dropped"`
	// Failed are observations of batches that got no answer at all.
	Failed int `json:"failed"`
	// Batches is how many batches were posted.
	Batches int `json:"batches"`
}

// Balanced reports whether every observation is accounted for.
func (t Tally) Balanced() bool {
	return t.Sent == t.Accepted+t.Duplicates+t.Refused+t.Dropped+t.Failed
}

type pending struct {
	heard time.Time
	due   time.Time
	obs   []gen.RIDObservation
}

// Receiver is a simulated Remote ID receiver: it encodes each aircraft's
// state through uspace-core odid (real frames), signs each batch with a
// key generated at run time (auth.SignReport), and posts it to
// rid-ingest's POST /v1/rid/observations with the X-Lab-Scenario header,
// with a configurable drop rate, delivery latency and backlog flag.
type Receiver struct {
	ID             string
	LatDeg, LonDeg float64
	// Scenario is the X-Lab-Scenario value (the stack's name); empty
	// sends no header.
	Scenario string
	// DropRate drops each observation with this probability, from a
	// generator seeded with Seed.
	DropRate float64
	Seed     uint64
	// Drop, when set, drops an observation it says true for (a
	// scenario's exact drop); it is asked before DropRate.
	Drop func(step int, a *Aircraft, t odid.MessageType) bool
	// Latency delays every batch's delivery: it is signed and posted
	// Latency after it was heard (SC-11).
	Latency time.Duration
	// Backlog marks every batch as backlog (T-04).
	Backlog bool
	// Period is the step period (1 s when 0: aircraft paths at 1 Hz).
	Period time.Duration

	s      *Stack
	url    string
	bearer string
	secret []byte
	n      geoid.Undulator
	client *http.Client

	mu      sync.Mutex
	rng     *rand.Rand
	tally   Tally
	queue   []pending
	nonce   int
	answers map[int]int
}

var cheapHasher = sync.OnceValues(func() (*passhash.Hasher, error) {
	return passhash.New(passhash.Params{MemoryKiB: 8, Time: 1, Threads: 1})
})

// NewReceiver registers receiver id, pinned at (lat, lon), in the run's
// key set (as api writes it: a bearer hash and an HMAC secret generated
// now, never stored anywhere else) and returns its simulator posting to
// ri.
func (s *Stack) NewReceiver(id string, latDeg, lonDeg float64, ri *RIDIngest) *Receiver {
	s.T.Helper()
	creds, secret, err := receivers.GenerateCredentials(id, 1)
	if err != nil {
		s.T.Fatalf("ltest: receiver credentials: %v", err)
	}
	h, err := cheapHasher()
	if err != nil {
		s.T.Fatalf("ltest: hasher: %v", err)
	}
	hash, err := h.Hash(creds.BearerKey)
	if err != nil {
		s.T.Fatalf("ltest: hash: %v", err)
	}
	g, err := geoid.Load(GeoidFile())
	if err != nil {
		s.T.Fatalf("ltest: geoid: %v", err)
	}
	r := &Receiver{ID: id, LatDeg: latDeg, LonDeg: lonDeg, Scenario: s.Name, s: s, url: ri.BaseURL,
		bearer: "Bearer " + creds.BearerKey, secret: secret, n: g, client: &http.Client{Timeout: 10 * time.Second},
		answers: map[int]int{}}
	s.PutReceiver(receivers.Entry{ReceiverID: id, Status: receivers.StatusEnabled, LatDeg: latDeg, LonDeg: lonDeg, Version: 1,
		Keys: []receivers.KeyGeneration{{Generation: 1, BearerHash: hash, HMACSecretHex: hex.EncodeToString(secret)}}})
	s.mu.Lock()
	s.sims = append(s.sims, r)
	ri.registered++
	want := float64(ri.registered)
	s.mu.Unlock()
	// The ingest follows the key set; a batch before it holds this key
	// would be refused, so wait until its status line counts every
	// receiver registered so far.
	ri.WaitLine("status", func(m map[string]any) bool { n, _ := m["receivers"].(float64); return n >= want }, 20*time.Second)
	return r
}

// PutReceiver writes a key-set entry as api does (KV, key the receiver
// id).
func (s *Stack) PutReceiver(e receivers.Entry) {
	s.T.Helper()
	if err := e.Validate(); err != nil {
		s.T.Fatalf("ltest: receiver entry: %v", err)
	}
	raw, err := json.Marshal(e)
	if err != nil {
		s.T.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	kv, err := s.BP.JS.KeyValue(ctx, s.RIDKeysBucket)
	if err != nil {
		s.T.Fatalf("ltest: key-set bucket: %v", err)
	}
	if _, err := kv.Put(ctx, e.ReceiverID, raw); err != nil {
		s.T.Fatalf("ltest: key-set put: %v", err)
	}
}

// Tally is the receiver's account so far.
func (r *Receiver) Tally() Tally {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tally
	t.RefusedBy = make(map[string]int, len(r.tally.RefusedBy))
	for k, v := range r.tally.RefusedBy {
		t.RefusedBy[k] = v
	}
	return t
}

// Answers are how many batches got each HTTP status (0: no answer).
func (r *Receiver) Answers() map[int]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[int]int, len(r.answers))
	for k, v := range r.answers {
		out[k] = v
	}
	return out
}

func (r *Receiver) period() time.Duration {
	if r.Period > 0 {
		return r.Period
	}
	return time.Second
}

func (r *Receiver) drop(step int, a *Aircraft, t odid.MessageType) bool {
	if r.Drop != nil && r.Drop(step, a, t) {
		return true
	}
	if r.DropRate <= 0 {
		return false
	}
	if r.rng == nil {
		r.rng = rand.New(rand.NewPCG(r.Seed, 25)) //nolint:gosec // a seeded simulation of radio loss, reproducible by design
	}
	return r.rng.Float64() < r.DropRate
}

// tenths is the Location timestamp of a broadcast at t: tenths of a
// second after the UTC hour, as the field holds them (T-07).
func tenths(t time.Time) *float64 {
	v := float64(t.Sub(t.Truncate(time.Hour))/(100*time.Millisecond)) / 10
	return &v
}

var odidEpoch = time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)

// Messages are the ODID messages aircraft a broadcasts at step, heard
// at heard, in the order a pack carries them, or nil when silent.
func (r *Receiver) Messages(a *Aircraft, step int, heard time.Time) ([]odid.Message, error) {
	st := a.Path(step)
	if st.Silent {
		return nil, nil
	}
	serial, opID := a.Serial, a.OperatorID
	if st.Serial != nil {
		serial = *st.Serial
	}
	if st.OperatorID != nil {
		opID = *st.OperatorID
	}
	n, err := r.n.UndulationM(core.LatLon{LatDeg: st.LatDeg, LonDeg: st.LonDeg})
	if err != nil {
		return nil, fmt.Errorf("geoid at %v %v: %w", st.LatDeg, st.LonDeg, err)
	}
	lat, lon := st.LatDeg, st.LonDeg
	hae := geoid.HAEFromAMSL(st.AltAMSLM, n)
	// The pressure altitude of a standard day, where it equals AMSL:
	// carried, but the ingest uses the geodetic altitude at this
	// accuracy (R-08).
	baro := st.AltAMSLM
	speed, dir := st.SpeedMS, st.TrackDeg
	loc := odid.Location{Status: st.Status, LatDeg: &lat, LonDeg: &lon, AltHAEM: &hae, AltBaroM: &baro,
		SpeedHorizontalMS: &speed, DirectionDeg: &dir, HorizAccuracy: 11, VertAccuracy: 4, BaroAccuracy: 4, SpeedAccuracy: 3, TSAccuracy: 2}
	if step >= a.UTCFromStep {
		loc.SecondsAfterHour = tenths(heard)
	}
	every := max(a.BasicIDEvery, 1)
	identityStep := !a.OnePerDatagram || step%every == 0
	var out []odid.Message
	if serial != "" && identityStep {
		out = append(out, odid.BasicID{IDType: odid.IDTypeSerial, UAType: 2, UAID: serial})
	}
	out = append(out, loc)
	if a.System && identityStep {
		oLat, oLon := r.LatDeg, r.LonDeg
		out = append(out, odid.System{OperatorLocationType: 0, ClassificationType: 1, OperatorLatDeg: &oLat, OperatorLonDeg: &oLon,
			AreaCount: 1, CategoryEU: 1, ClassEU: 1, TimestampS: uint32(heard.Sub(odidEpoch) / time.Second)})
	}
	if opID != "" && identityStep {
		out = append(out, odid.OperatorID{OperatorIDType: 0, OperatorID: opID})
	}
	return out, nil
}

// observations encodes one step of a as observations (one pack, or one
// per message), dropping what the link drops.
func (r *Receiver) observations(a *Aircraft, step int, heard time.Time) ([]gen.RIDObservation, error) {
	msgs, err := r.Messages(a, step, heard)
	if err != nil || len(msgs) == 0 {
		return nil, err
	}
	tx := a.Transmitter
	if st := a.Path(step); st.Transmitter != nil {
		tx = *st.Transmitter
	}
	rx := heard.UTC().Truncate(time.Millisecond)
	rssi := -70.0
	one := func(payload []byte, t odid.MessageType) *gen.RIDObservation {
		r.tally.Sent++
		if r.drop(step, a, t) {
			r.tally.Dropped++
			return nil
		}
		return &gen.RIDObservation{Transmitter: tx, PayloadHex: hex.EncodeToString(payload), RssiDbm: &rssi, RxTs: &rx}
	}
	var out []gen.RIDObservation
	if a.OnePerDatagram {
		for _, m := range msgs {
			b, err := odid.Encode(m)
			if err != nil {
				return nil, err
			}
			if o := one(b[:], m.Type()); o != nil {
				out = append(out, *o)
			}
		}
		return out, nil
	}
	b, err := odid.EncodePack(msgs)
	if err != nil {
		return nil, err
	}
	if o := one(b, odid.TypeMessagePack); o != nil {
		out = append(out, *o)
	}
	return out, nil
}

// Step builds step of every aircraft as one batch heard now, queues it
// for delivery after Latency, and posts every batch that is due. An
// error is a frame the codec refuses: nothing of the step is sent.
func (r *Receiver) Step(step int, acs ...*Aircraft) error {
	now := time.Now()
	r.mu.Lock()
	var obs []gen.RIDObservation
	for _, a := range acs {
		o, err := r.observations(a, step, now)
		if err != nil {
			r.mu.Unlock()
			return fmt.Errorf("receiver %s, step %d: %w", r.ID, step, err)
		}
		obs = append(obs, o...)
	}
	if len(obs) > 0 {
		r.queue = append(r.queue, pending{heard: now, due: now.Add(r.Latency), obs: obs})
	}
	r.mu.Unlock()
	r.flush(now)
	return nil
}

// flush posts the queued batches due at now.
func (r *Receiver) flush(now time.Time) {
	for {
		r.mu.Lock()
		if len(r.queue) == 0 || r.queue[0].due.After(now.Add(r.period()/10)) {
			r.mu.Unlock()
			return
		}
		b := r.queue[0]
		r.queue = r.queue[1:]
		r.mu.Unlock()
		r.post(b)
	}
}

// drain posts every queued batch at its due time.
func (r *Receiver) drain() {
	for {
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.mu.Unlock()
			return
		}
		due := r.queue[0].due
		r.mu.Unlock()
		if wait := time.Until(due); wait > 0 {
			<-time.After(wait)
		}
		r.flush(time.Now())
	}
}

// post signs and posts one batch now and accounts for its answer.
func (r *Receiver) post(b pending) {
	r.mu.Lock()
	r.nonce++
	nonce := fmt.Sprintf("%s-%d-%d", r.ID, b.heard.UnixMilli(), r.nonce)
	r.mu.Unlock()
	backlog := r.Backlog
	for len(b.obs) > 0 {
		part := b.obs[:min(len(b.obs), receivers.MaxObservations)]
		b.obs = b.obs[len(part):]
		body, err := json.Marshal(gen.RIDObservationBatch{ReceiverId: r.ID, SentAtMs: time.Now().UnixMilli(), Nonce: nonce + fmt.Sprintf("-%d", len(b.obs)),
			Backlog: &backlog, Observations: part})
		if err != nil {
			r.s.T.Errorf("ltest: batch: %v", err)
			return
		}
		status, ack, slug := r.send(body)
		r.mu.Lock()
		r.tally.Batches++
		r.answers[status]++
		switch status {
		case http.StatusAccepted:
			r.tally.Accepted += ack.Accepted
			r.tally.Duplicates += ack.Duplicates
			if lost := len(part) - ack.Accepted - ack.Duplicates; lost != 0 {
				r.tally.Failed += lost
			}
		case 0:
			r.tally.Failed += len(part)
		default:
			r.tally.Refused += len(part)
			r.tally.RefusedBatch++
			if r.tally.RefusedBy == nil {
				r.tally.RefusedBy = map[string]int{}
			}
			r.tally.RefusedBy[fmt.Sprintf("%d %s", status, slug)] += len(part)
		}
		r.mu.Unlock()
	}
}

func (r *Receiver) send(body []byte) (int, gen.RIDObservationAck, string) {
	var ack gen.RIDObservationAck
	req, err := http.NewRequest(http.MethodPost, r.url+"/v1/rid/observations", bytes.NewReader(body))
	if err != nil {
		return 0, ack, ""
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", r.bearer)
	req.Header.Set(receivers.SignatureHeader, auth.SignReport(r.secret, body))
	if r.Scenario != "" {
		req.Header.Set(receivers.LabScenarioHeader, r.Scenario)
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return 0, ack, ""
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode == http.StatusAccepted {
		_ = json.Unmarshal(raw, &ack)
		return resp.StatusCode, ack, ""
	}
	var p struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(raw, &p)
	slug := p.Type
	if i := bytes.LastIndexByte([]byte(slug), '/'); i >= 0 {
		slug = slug[i+1:]
	}
	return resp.StatusCode, ack, slug
}
