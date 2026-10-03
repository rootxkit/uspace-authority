package certs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/cisp"
	pggen "github.com/rootxkit/uspace-authority/internal/store/pg/gen"
)

var t0 = time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)

func usspRow(code string) pggen.Certificate {
	return pggen.Certificate{
		ID: fmt.Sprintf("%032x", len(code)) + "", Holder: HolderUSSP, HolderName: "USSP " + code, HolderEmail: "ops@" + strings.ToLower(code) + ".example.test",
		HolderUrl: "https://" + strings.ToLower(code) + ".example.test/contact", Code: code, ClientID: "ussp-" + code + "-01",
		BaseUrl: "https://" + strings.ToLower(code) + ".example.test", Services: []string{ServiceNetworkIdentification, ServiceGeoAwareness},
		Limitations: []string{}, TermsUrl: "https://" + strings.ToLower(code) + ".example.test/terms", IssuedAt: t0,
		ValidUntil: t0.AddDate(1, 0, 0), Operations: OpsOperating, Status: StatusOperating,
	}
}

func checkList(t *testing.T, payload []byte) {
	t.Helper()
	s, err := cisp.LoadSchemas()
	if err != nil {
		t.Fatal(err)
	}
	if _, probs, _ := s.CheckPublication(cisp.DatasetUSSPList, payload); len(probs) > 0 {
		t.Fatalf("the list does not pass the pinned cis/ussp_list/v1: %v\n%s", probs, payload)
	}
}

// The list validates against the pinned cis/ussp_list/v1 (M7, WP-6's
// copy under api/clients/cisp-schemas/): with operating and limited
// USSPs, an empty contact member left out, and empty.
func TestListValidatesAgainstThePinnedSchema(t *testing.T) {
	a, b := usspRow("AAA1"), usspRow("BBB2")
	b.ID = strings.Repeat("b", 32)
	b.Status, b.Limited, b.Limitations = StatusLimited, true, []string{"VLOS operations only"}
	b.HolderEmail, b.HolderUrl, b.HolderPhone = "", "", "+995 32 200 00 00"
	payload, n, err := BuildList([]pggen.Certificate{a, b}, t0.Add(time.Hour))
	if err != nil || n != 2 {
		t.Fatal(n, err)
	}
	checkList(t, payload)
	var got map[string]any
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	first := got["ussps"].([]any)[0].(map[string]any)
	if got["schema"] != ListSchema || first["ussp_id"] != "AAA1" || first["certificate_id"] != a.ID || first["valid_from"] != "2026-10-01T08:00:00Z" {
		t.Fatalf("%s", payload)
	}
	second := got["ussps"].([]any)[1].(map[string]any)
	if second["status"] != "limited" || second["certification_limitations"].([]any)[0] != "VLOS operations only" {
		t.Fatalf("%s", payload)
	}
	if _, has := second["contact"].(map[string]any)["email"]; has {
		t.Fatalf("an empty e-mail is sent: %s", payload)
	}
	empty, n, err := BuildList(nil, t0)
	if err != nil || n != 0 {
		t.Fatal(err)
	}
	checkList(t, empty)
	// E-01: the schema check is not blind: a list it must refuse.
	s, _ := cisp.LoadSchemas()
	bad := strings.Replace(string(payload), `"ussp_id":"AAA1"`, `"ussp_id":"BBB2"`, 1)
	if _, probs, _ := s.CheckPublication(cisp.DatasetUSSPList, []byte(bad)); len(probs) == 0 {
		t.Fatal("a repeated ussp_id passed the check")
	}
}

// E-10: one USSP past the list's bound refuses the list, never cuts it.
func TestListOverItsBoundIsRefused(t *testing.T) {
	rows := make([]pggen.Certificate, MaxListed)
	for i := range rows {
		rows[i] = usspRow(fmt.Sprintf("U%04d", i))
		rows[i].ID = fmt.Sprintf("%032x", i)
	}
	payload, n, err := BuildList(rows, t0)
	if err != nil || n != MaxListed {
		t.Fatal(n, err)
	}
	checkList(t, payload)
	rows = slices.Concat(rows, []pggen.Certificate{usspRow("OVER")})
	if _, _, err := BuildList(rows, t0); !errors.Is(err, ErrListTooLong) {
		t.Fatalf("%v", err)
	}
}

func TestListDigest(t *testing.T) {
	a := usspRow("AAA1")
	if listDigest(nil) != "" {
		t.Fatal("the empty list has a digest")
	}
	d1 := listDigest([]pggen.Certificate{a})
	a.RowVersion++
	if d2 := listDigest([]pggen.Certificate{a}); d2 == d1 || d2 == "" {
		t.Fatal("a changed certificate keeps the digest")
	}
}

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// schemaBlock is the text of components.schemas.<name>.
func schemaBlock(spec, name string) string {
	start := strings.Index(spec, "\n    "+name+":\n")
	if start < 0 {
		return ""
	}
	lines := strings.Split(spec[start+1:], "\n")
	out := []string{lines[0]}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "     ") {
			break
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// What the public register (Art. 18(a)) must never carry: the holder's
// address and contact, its client, its conditions and anything that
// names a person (CLAUDE.md rule 6, as WP-3's schema grep).
var notPublic = regexp.MustCompile(`(?m)^\s*(name|address|holder_address|contact|email|holder_email|phone|holder_phone|holder_url|url|client_id|conditions|status_changed_by|created_by|updated_by|base_url|terms_url):`)

// privateIn lists the private properties of schema name, following
// every $ref.
func privateIn(spec, name string, seen map[string]bool) []string {
	if seen[name] {
		return nil
	}
	seen[name] = true
	block := schemaBlock(spec, name)
	var out []string
	for _, m := range notPublic.FindAllStringSubmatch(block, -1) {
		out = append(out, name+"."+m[1])
	}
	for _, m := range regexp.MustCompile(`#/components/schemas/(\w+)`).FindAllStringSubmatch(block, -1) {
		out = append(out, privateIn(spec, m[1], seen)...)
	}
	return out
}

// The register's response schema carries none of them; the admin
// certificate does (E-01: the grep finds them where they are); and the
// handler fills exactly the register's properties.
func TestRegisterSchemaHasNoPrivateProperty(t *testing.T) {
	spec := readSpec(t)
	if schemaBlock(spec, "CertificateRegisterEntry") == "" {
		t.Fatal("schema CertificateRegisterEntry not found")
	}
	if got := privateIn(spec, "CertificateRegister", map[string]bool{}); len(got) > 0 {
		t.Errorf("the public register carries %v", got)
	}
	if got := privateIn(spec, "Certificate", map[string]bool{}); len(got) < 5 {
		t.Fatalf("the grep finds %v in Certificate: it is blind", got)
	}
	out := RegisterOf([]pggen.CertificateRegisterRow{{ID: strings.Repeat("a", 32), Holder: HolderUSSP, HolderName: "X",
		Code: "X1", Services: []string{ServiceWeather}, Status: StatusOperating, IssuedAt: t0, ValidUntil: t0.AddDate(1, 0, 0)}}, t0)
	b, _ := json.Marshal(out)
	var doc struct {
		Certificates []map[string]any `json:"certificates"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || len(doc.Certificates) != 1 {
		t.Fatalf("%s", b)
	}
	keys := make([]string, 0, len(doc.Certificates[0]))
	for k := range doc.Certificates[0] {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "certificate_id,code,holder,holder_name,limitations,services,status,valid_from,valid_until" {
		t.Fatalf("register entry %v", keys)
	}
}
