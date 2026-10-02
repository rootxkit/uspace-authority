package registry

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
)

// piiProperties are the property names of personal data (spec 02 F8:
// "no names, addresses, phone numbers or emails"; spec 06 §5).
var piiProperties = []string{
	"name", "full_name", "legal_name", "date_of_birth", "legal_identification_number",
	"postal_address", "address", "contact_email", "email", "contact_phone", "phone",
	"insurance_policy_number", "person_ref", "person_ref_last4",
}

var piiKey = regexp.MustCompile(`(?m)^\s*(` + strings.Join(piiProperties, "|") + `):`)

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
	rest := spec[start+1:]
	lines := strings.Split(rest, "\n")
	out := []string{lines[0]}
	for _, l := range lines[1:] {
		if strings.TrimSpace(l) != "" && !strings.HasPrefix(l, "     ") {
			break
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

var refPattern = regexp.MustCompile(`#/components/schemas/(\w+)`)

// piiIn lists the personal property names a schema carries, following
// every $ref.
func piiIn(spec, name string, seen map[string]bool) []string {
	if seen[name] {
		return nil
	}
	seen[name] = true
	block := schemaBlock(spec, name)
	var out []string
	for _, m := range piiKey.FindAllStringSubmatch(block, -1) {
		out = append(out, name+"."+m[1])
	}
	for _, m := range refPattern.FindAllStringSubmatch(block, -1) {
		out = append(out, piiIn(spec, m[1], seen)...)
	}
	return out
}

type contractOp struct {
	id        string
	roles     []string
	scope     string
	public    bool
	responses []string // schemas of the 2xx responses
}

// operations reads every operation of the contract with its access rule
// and its success response schemas.
func operations(spec string) []contractOp {
	var ops []contractOp
	var cur *contractOp
	inResponses, success := false, false
	idRe := regexp.MustCompile(`^      operationId: (\w+)`)
	rolesRe := regexp.MustCompile(`^      x-roles: \[([^\]]*)\]`)
	scopeRe := regexp.MustCompile(`^      x-scope: (\S+)`)
	statusRe := regexp.MustCompile(`^        "(\d{3})":`)
	for _, l := range strings.Split(spec, "\n") {
		if strings.HasPrefix(l, "components:") {
			break
		}
		if m := idRe.FindStringSubmatch(l); m != nil {
			ops = append(ops, contractOp{id: strings.ToUpper(m[1][:1]) + m[1][1:]})
			cur, inResponses, success = &ops[len(ops)-1], false, false
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case rolesRe.MatchString(l):
			for r := range strings.SplitSeq(rolesRe.FindStringSubmatch(l)[1], ",") {
				cur.roles = append(cur.roles, strings.TrimSpace(r))
			}
		case scopeRe.MatchString(l):
			cur.scope = scopeRe.FindStringSubmatch(l)[1]
		case strings.TrimSpace(l) == "security: []":
			cur.public = true
		case strings.HasPrefix(l, "      responses:"):
			inResponses = true
		case inResponses && statusRe.MatchString(l):
			success = strings.HasPrefix(statusRe.FindStringSubmatch(l)[1], "2")
		case inResponses && strings.HasPrefix(l, "        default:"):
			success = false
		case inResponses && success && refPattern.MatchString(l):
			cur.responses = append(cur.responses, refPattern.FindStringSubmatch(l)[1])
		}
	}
	return ops
}

// CLAUDE.md rule 6 on the contract, fail closed: an operation whose
// success response carries a personal property is open only to the
// registry's PII roles, never public, never a machine scope, never
// viewer. The F8 responses carry none. The check runs over every
// operation of the file, so a later response that grows a name field is
// caught wherever it is.
func TestPersonalDataReachesNoPublicViewerOrMachineResponse(t *testing.T) {
	spec := readSpec(t)
	ops := operations(spec)
	if len(ops) < 40 {
		t.Fatalf("parsed %d operations; the parser lost the contract", len(ops))
	}
	piiOps := map[string]bool{}
	for _, op := range ops {
		var found []string
		for _, r := range op.responses {
			found = append(found, piiIn(spec, r, map[string]bool{})...)
		}
		if len(found) == 0 {
			continue
		}
		piiOps[op.id] = true
		if op.public || op.scope != "" || len(op.roles) == 0 {
			t.Errorf("%s returns %v to a public or machine caller", op.id, found)
		}
		for _, r := range op.roles {
			if !slices.Contains(apiserver.PIIRoles, r) {
				t.Errorf("%s returns %v to role %s", op.id, found, r)
			}
		}
	}
	// E-01: the check finds personal data where it is (the personal-data
	// operations), so its silence elsewhere means something.
	for _, op := range []string{"GetRegistryOperatorPersonalData", "GetRegistryPilotPersonalData"} {
		if !piiOps[op] {
			t.Errorf("%s: no personal property found; the check is blind", op)
		}
	}
	// The F8 responses, by name, carry none.
	for _, s := range []string{"RegistryValidity", "RegistryValidityList", "RegistryChangePage", "RegistryOperator", "RegistryUAS", "RegistryPilot"} {
		if found := piiIn(spec, s, map[string]bool{}); len(found) != 0 {
			t.Errorf("%s carries %v", s, found)
		}
		if schemaBlock(spec, s) == "" {
			t.Errorf("schema %s not found", s)
		}
	}
}

func TestContractCheckFindsAPlantedName(t *testing.T) {
	spec := "components:\n  schemas:\n    Clean:\n      properties:\n        status: {type: string}\n        inner: {$ref: \"#/components/schemas/Leaky\"}\n    Leaky:\n      properties:\n        contact_email: {type: string}\n"
	if got := piiIn(spec, "Clean", map[string]bool{}); len(got) != 1 || got[0] != "Leaky.contact_email" {
		t.Fatalf("got %v", got)
	}
	ops := operations("paths:\n  /x:\n    get:\n      operationId: getX\n      x-scope: registry.validate\n      responses:\n        \"200\":\n          content:\n            application/json:\n              schema:\n                $ref: \"#/components/schemas/Clean\"\n        default:\n          $ref: \"#/components/schemas/Problem\"\n")
	if len(ops) != 1 || ops[0].scope != "registry.validate" || !slices.Equal(ops[0].responses, []string{"Clean"}) {
		t.Fatalf("ops %+v", ops)
	}
}

// The personal-data operations name exactly the PII roles in code.
func TestPersonalDataOperationsAreHeldToThePIIRoles(t *testing.T) {
	for _, op := range []string{"GetRegistryOperatorPersonalData", "GetRegistryPilotPersonalData"} {
		if !slices.Equal(apiserver.Roles[op], apiserver.PIIRoles) {
			t.Errorf("%s: roles %v, want %v", op, apiserver.Roles[op], apiserver.PIIRoles)
		}
	}
	if slices.Contains(apiserver.PIIRoles, apiserver.RoleViewer) {
		t.Error("viewer may read personal data")
	}
}
