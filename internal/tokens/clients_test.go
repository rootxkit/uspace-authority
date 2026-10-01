package tokens

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-core/core"

	"github.com/rootxkit/uspace-authority/internal/audit"
)

func fieldsOf(err error) []string {
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

// E-01 at registration: a scope outside table B is refused, beside a
// registration that accepts every grantable row; every field problem is
// named at once.
func TestRegistrationRefusesWhatTheTokenEndpointWouldRefuse(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()
	var all []string
	for _, s := range Catalogue() {
		if CheckGrantable(s.Name, LabClientID) == nil {
			all = append(all, s.Name)
		}
	}
	if _, _, err := f.parts.Registry.Create(ctx, ClientInput{ID: "lab-01", Scopes: all, AuthMethod: MethodSecretPost}, admin); err != nil {
		t.Fatalf("every grantable row: %v", err)
	}
	_, _, err := f.parts.Registry.Create(ctx, ClientInput{
		ID: "cisp-1", Scopes: []string{"rid.observe", "dp.observe", "cis.read", "cis.read", "cis.publish:ats_data", "ussp.geo"},
		Audiences: []string{"Upper.example.test", "h:1", "ok.example.test", "ok.example.test"}, AuthMethod: "client_secret_basic",
		Note: strings.Repeat("n", MaxNoteLen+1), MTLSSubject: strings.Repeat("m", MaxMTLSSubjectLen+1),
		CertificateID: strings.Repeat("c", MaxCertificateID+1),
	}, admin)
	got := fieldsOf(err)
	for _, want := range []string{"client_id", "scopes[0]", "scopes[3]", "scopes[4]", "scopes[5]", "audiences[0]", "audiences[1]", "audiences[3]",
		"auth_method", "note", "mtls_subject", "certificate_id"} {
		if !slices.Contains(got, want) {
			t.Errorf("no error on %s: %v", want, got)
		}
	}
	// dp.observe for a client other than lab-01 is refused by name.
	_, _, err = f.parts.Registry.Create(ctx, ClientInput{ID: "cisp-01", Scopes: []string{"dp.observe"}, AuthMethod: MethodSecretPost}, admin)
	if !slices.Contains(fieldsOf(err), "scopes[0]") || !strings.Contains(err.Error(), "lab-01") {
		t.Fatalf("dp.observe for cisp-01: %v", err)
	}
	for name, in := range map[string]ClientInput{
		"no scopes":      {ID: "cisp-01", AuthMethod: MethodSecretPost},
		"too many":       {ID: "cisp-01", Scopes: slices.Repeat([]string{"cis.read"}, MaxScopes+1), AuthMethod: MethodSecretPost},
		"many audiences": {ID: "cisp-01", Scopes: []string{"cis.read"}, Audiences: slices.Repeat([]string{"a"}, MaxAudiences+1), AuthMethod: MethodSecretPost},
		"jwks on secret": {ID: "cisp-01", Scopes: []string{"cis.read"}, AuthMethod: MethodSecretPost, JWKS: clientJWKS(t, 3, "k")},
		"no jwks":        {ID: "cisp-01", Scopes: []string{"cis.read"}, AuthMethod: MethodPrivateKeyJWT},
	} {
		if _, _, err := f.parts.Registry.Create(ctx, in, admin); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if n := len(f.st.eventsOf(audit.EventOAuthClientCreated)); n != 1 {
		t.Fatalf("%d creation events", n)
	}
}

func TestUpdateRecordsBeforeAndAfter(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()
	f.register(t, "cisp-01", []string{"cis.read"}, nil)
	scopes := []string{"cis.read", "cis.publish:restrictions"}
	auds := []string{cispHost}
	note := "onboarded"
	c, err := f.parts.Registry.Update(ctx, "cisp-01", ClientPatch{Scopes: &scopes, Audiences: &auds, Note: &note}, admin)
	if err != nil || !slices.Equal(c.Scopes, scopes) || c.Note != note || c.UpdatedBy != "admin-1" {
		t.Fatalf("%+v %v", c, err)
	}
	ev := f.st.eventsOf(audit.EventOAuthClientUpdated)
	p := ev[0].Payload.(map[string]any)
	if !slices.Equal(p["before"].(map[string]any)["scopes"].([]string), []string{"cis.read"}) {
		t.Fatalf("payload %v", p)
	}
	bad := "paused"
	if _, err := f.parts.Registry.Update(ctx, "cisp-01", ClientPatch{Status: &bad}, admin); !slices.Contains(fieldsOf(err), "status") {
		t.Fatalf("status: %v", err)
	}
	var nilAud []string
	if c, err := f.parts.Registry.Update(ctx, "cisp-01", ClientPatch{Audiences: &nilAud}, admin); err != nil || c.Audiences == nil {
		t.Fatalf("clearing audiences: %+v %v", c, err)
	}
	if c.String() != "client cisp-01 (cisp, client_secret_post, active)" {
		t.Fatalf("%q", c.String())
	}
}

func TestRegistryStoreFailures(t *testing.T) {
	f := newFixture(t, fixtureOpts{})
	ctx := context.Background()
	f.st.failRecord = true
	if _, _, err := f.parts.Registry.Create(ctx, ClientInput{ID: "cisp-01", Scopes: []string{"cis.read"}, AuthMethod: MethodSecretPost}, admin); err == nil {
		t.Fatal("created without its event")
	}
	if _, err := f.st.ClientRecord(ctx, "cisp-01"); !errors.Is(err, ErrNotFound) {
		t.Fatal("the client survived the rolled-back transaction")
	}
	f.st.failRecord = false
	f.register(t, "cisp-01", []string{"cis.read"}, nil)
	f.st.failRecord = true
	note := "x"
	if _, err := f.parts.Registry.Update(ctx, "cisp-01", ClientPatch{Note: &note}, admin); err == nil {
		t.Fatal("updated without its event")
	}
	f.st.failReads = true
	if _, err := f.parts.Registry.Get(ctx, "cisp-01"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("read outage: %v", err)
	}
}
