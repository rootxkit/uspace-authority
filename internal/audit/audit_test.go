package audit

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-core/core"
)

func fields(err error) []string {
	var out []string
	var walk func(error)
	walk = func(e error) {
		if j, ok := e.(interface{ Unwrap() []error }); ok {
			for _, x := range j.Unwrap() {
				walk(x)
			}
			return
		}
		var fe *core.FieldError
		if errors.As(e, &fe) {
			out = append(out, fe.Field)
		}
	}
	if err != nil {
		walk(err)
	}
	return out
}

func validEvent() Event {
	return Event{
		Actor:      Actor{Type: ActorUser, ID: "user-1", Realm: RealmConsole},
		EntityType: "authority_policy", EntityID: "2", EventType: EventPolicyCreated,
	}
}

func TestValidateAcceptsAWellFormedEvent(t *testing.T) {
	if err := DefaultCatalogue().Validate(validEvent()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateNamesEveryFieldAtFault(t *testing.T) {
	ev := Event{Actor: Actor{Type: "robot", Realm: "lab"}, EventType: "policy_creatd"}
	got := strings.Join(fields(DefaultCatalogue().Validate(ev)), ",")
	if got != "actor_type,actor_id,realm,entity_type,event_type" {
		t.Fatalf("fields %s", got)
	}
	ev.EventType = ""
	if got := fields(DefaultCatalogue().Validate(ev)); got[len(got)-1] != "event_type" {
		t.Fatalf("empty event type: %v", got)
	}
}

// CLAUDE.md rule 6: a PII read without a purpose is refused; the same
// read with a purpose is accepted, and a non-PII event needs none (E-01).
func TestPIIViewNeedsAPurpose(t *testing.T) {
	cat := DefaultCatalogue()
	cat["registry_record_viewed"] = Kind{PIIView: true}
	ev := validEvent()
	ev.EventType = "registry_record_viewed"
	err := cat.Validate(ev)
	if got := fields(err); len(got) != 1 || got[0] != "purpose" || !strings.Contains(err.Error(), "pii_view") {
		t.Fatalf("refusal: %v", err)
	}
	ev.Purpose = "authorisation"
	if err := cat.Validate(ev); err != nil {
		t.Fatalf("with a purpose: %v", err)
	}
	if err := cat.Validate(validEvent()); err != nil {
		t.Fatalf("non-PII without a purpose: %v", err)
	}
}

func row() Row {
	realm := RealmConsole
	return Row{
		ID: 7, TS: time.Date(2026, 1, 31, 23, 59, 59, 123456789, time.FixedZone("x", 4*3600)),
		ActorType: "user", ActorID: "user-1", Realm: &realm, EntityType: "authority_policy",
		EventType: EventPolicyCreated, Payload: []byte(`{"b": 1, "a": {"y": [1, 2], "x": "<&>"}}`),
		PrevHash: GenesisHash,
	}
}

func TestCanonicalIsFixedOrderUTCMicrosecondsAndSortedPayload(t *testing.T) {
	c, err := Canonical(row())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":7,"ts":"2026-01-31T19:59:59.123456Z","actor_type":"user","actor_id":"user-1","realm":"console",` +
		`"purpose":null,"entity_type":"authority_policy","entity_id":null,"event_type":"policy_created",` +
		`"payload":{"a":{"x":"<&>","y":[1,2]},"b":1},"prev_hash":"` + GenesisHash + `"}`
	if string(c) != want {
		t.Fatalf("canonical\n got %s\nwant %s", c, want)
	}
}

func TestHashIsStableAndCoversEveryField(t *testing.T) {
	base, err := Hash(row())
	if err != nil {
		t.Fatal(err)
	}
	same := row()
	same.Payload = []byte(`{"a":{"y":[1,2],"x":"<&>"},"b":1}`) // key order and spacing do not matter
	same.Hash = "ignored: hash is not hashed"
	if h, _ := Hash(same); h != base {
		t.Fatalf("reordered payload changed the hash")
	}
	purpose := "x"
	mutations := map[string]func(*Row){
		"id":        func(r *Row) { r.ID++ },
		"ts":        func(r *Row) { r.TS = r.TS.Add(time.Microsecond) },
		"actor":     func(r *Row) { r.ActorID = "user-2" },
		"realm":     func(r *Row) { r.Realm = nil },
		"purpose":   func(r *Row) { r.Purpose = &purpose },
		"entity":    func(r *Row) { r.EntityType = "events" },
		"entity_id": func(r *Row) { r.EntityID = &purpose },
		"type":      func(r *Row) { r.EventType = EventPolicyActivated },
		"payload":   func(r *Row) { r.Payload = []byte(`{"b":2,"a":{"y":[1,2],"x":"<&>"}}`) },
		"prev_hash": func(r *Row) { r.PrevHash = strings.Repeat("1", 64) },
	}
	for name, mutate := range mutations {
		r := row()
		mutate(&r)
		if h, err := Hash(r); err != nil || h == base {
			t.Errorf("%s: changing it left the hash %s (%v)", name, h, err)
		}
	}
}

func TestCanonicalPayloadRefusesWhatIsNotOneObject(t *testing.T) {
	for _, doc := range []string{`[1]`, `"x"`, `{"a":1} {"b":2}`, `{"a":`, ``} {
		if _, err := CanonicalPayload([]byte(doc)); err == nil {
			t.Errorf("%q accepted", doc)
		}
	}
	if got, err := CanonicalPayload([]byte(` { "n" : 1.50 , "big": 12345678901234567890 } `)); err != nil ||
		string(got) != `{"big":12345678901234567890,"n":1.50}` {
		t.Fatalf("numbers are kept as written: %s %v", got, err)
	}
}

func TestMonthStartIsTheUTCMonth(t *testing.T) {
	// 00:30 on 1 February in UTC+4 is still January in UTC.
	got := MonthStart(time.Date(2026, 2, 1, 0, 30, 0, 0, time.FixedZone("x", 4*3600)))
	if !got.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) || monthLockName(got) != "events:2026-01" {
		t.Fatalf("got %s", got)
	}
}

func TestRecordRefusesAnInvalidEventBeforeTheDatabase(t *testing.T) {
	w := &Writer{Catalogue: DefaultCatalogue()}
	// A nil Queries would panic if Record reached the database.
	if _, err := w.Record(t.Context(), nil, Event{}); err == nil || len(fields(err)) == 0 {
		t.Fatalf("got %v", err)
	}
	ev := validEvent()
	ev.Payload = math.Inf(1)
	if _, err := w.Record(t.Context(), nil, ev); err == nil || !strings.Contains(err.Error(), "payload") {
		t.Fatalf("unmarshalable payload: %v", err)
	}
}

func TestQueryRefusesALimitOutOfRangeAndAnEmptyWindow(t *testing.T) {
	for _, f := range []Filter{{Limit: -1}, {Limit: MaxQueryLimit + 1}} {
		if _, err := Query(t.Context(), nil, f); len(fields(err)) != 1 || fields(err)[0] != "limit" {
			t.Errorf("%+v: %v", f, err)
		}
	}
	at := time.Now()
	if _, err := Query(t.Context(), nil, Filter{From: at, To: at}); len(fields(err)) != 1 || fields(err)[0] != "to" {
		t.Errorf("empty window: %v", err)
	}
}
