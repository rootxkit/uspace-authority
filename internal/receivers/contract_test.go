package receivers_test

import (
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
	"github.com/rootxkit/uspace-authority/internal/receivers"
	"github.com/rootxkit/uspace-authority/internal/receivers/ingest"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

type receiverOp struct{ method, path string }

// receiverOps reads the x-receiver operations of the contract with their
// method and path.
func receiverOps(t *testing.T, spec string) map[string]receiverOp {
	t.Helper()
	pathRe := regexp.MustCompile(`^  (/\S+):$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|patch|delete):$`)
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	out := map[string]receiverOp{}
	var path, method, op string
	for line := range strings.SplitSeq(spec, "\n") {
		if m := pathRe.FindStringSubmatch(line); m != nil {
			path = m[1]
		}
		if m := methodRe.FindStringSubmatch(line); m != nil {
			method = strings.ToUpper(m[1])
		}
		if m := opRe.FindStringSubmatch(line); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
		}
		if strings.TrimSpace(line) == "x-receiver: true" {
			out[op] = receiverOp{method: method, path: path}
		}
	}
	return out
}

// The receiver operations are the same three in the contract, in
// apiserver.Receiver and in the generator's exclusions, and each is
// served on the contract's method and path.
func TestReceiverOperationsMatchTheContract(t *testing.T) {
	ops := receiverOps(t, read(t, "../../api/openapi.yaml"))
	if len(ops) != 3 {
		t.Fatalf("x-receiver operations %v", ops)
	}
	if !slices.Equal(slices.Sorted(maps.Keys(ops)), slices.Sorted(maps.Keys(apiserver.Receiver))) {
		t.Fatalf("contract %v, apiserver.Receiver %v", ops, apiserver.Receiver)
	}
	gen := read(t, "../../api/oapi-codegen.yaml")
	m := regexp.MustCompile(`exclude-operation-ids:\s*\[([^\]]*)\]`).FindStringSubmatch(gen)
	if m == nil {
		t.Fatal("no exclude-operation-ids")
	}
	var excluded []string
	for s := range strings.SplitSeq(m[1], ",") {
		s = strings.TrimSpace(s)
		if s != "getMetrics" {
			excluded = append(excluded, strings.ToUpper(s[:1])+s[1:])
		}
	}
	if !slices.Equal(slices.Sorted(slices.Values(excluded)), slices.Sorted(maps.Keys(ops))) {
		t.Fatalf("excluded %v, receiver operations %v", excluded, ops)
	}
	served := map[string]string{
		"GetRIDReceiverConfig":     receivers.PatternConfig,
		"PostRIDReceiverHeartbeat": receivers.PatternHeartbeat,
		"PostRIDObservations":      ingest.Pattern,
	}
	for op, o := range ops {
		if want := o.method + " " + o.path; served[op] != want {
			t.Errorf("%s served on %q, the contract says %q", op, served[op], want)
		}
	}
	for op := range ops {
		if _, ok := apiserver.Roles[op]; ok || apiserver.Public[op] || apiserver.Scopes[op] != "" {
			t.Errorf("%s is a receiver operation and has another rule", op)
		}
	}
}

// openAPIProps lists the property names of components.schemas.<name>.
func openAPIProps(t *testing.T, spec, name string) []string {
	t.Helper()
	start := strings.Index(spec, "\n    "+name+":\n")
	if start < 0 {
		t.Fatalf("no schema %s", name)
	}
	block := spec[start+1:]
	if end := regexp.MustCompile(`\n    [A-Za-z]`).FindStringIndex(block[5:]); end != nil {
		block = block[:end[0]+5]
	}
	var out []string
	inProps := false
	for line := range strings.SplitSeq(block, "\n") {
		switch {
		case line == "      properties:":
			inProps = true
		case inProps && strings.HasPrefix(line, "        ") && !strings.HasPrefix(line, "         "):
			out = append(out, strings.TrimSpace(strings.SplitN(line, ":", 2)[0]))
		case inProps && !strings.HasPrefix(line, "        "):
			inProps = false
		}
	}
	slices.Sort(out)
	return out
}

func jsonProps(m map[string]any) []string {
	props, _ := m["properties"].(map[string]any)
	return slices.Sorted(maps.Keys(props))
}

// schemas/rid/observation/v1.json, which this repository owns, and the
// contract's request body name the same members.
func TestObservationSchemaMatchesTheContract(t *testing.T) {
	spec := read(t, "../../api/openapi.yaml")
	var schema map[string]any
	if err := json.Unmarshal([]byte(read(t, "../../schemas/rid/observation/v1.json")), &schema); err != nil {
		t.Fatal(err)
	}
	if schema["$id"] != "https://schemas.uspace.ge/rid/observation/v1.json" {
		t.Fatalf("$id %v", schema["$id"])
	}
	// E-01: the parsers find the members, so equality means something.
	if n := len(openAPIProps(t, spec, "RIDObservationBatch")); n != 5 {
		t.Fatalf("the contract parser found %d batch members", n)
	}
	if got, want := jsonProps(schema), openAPIProps(t, spec, "RIDObservationBatch"); !slices.Equal(got, want) {
		t.Errorf("batch: schema %v, contract %v", got, want)
	}
	defs := schema["$defs"].(map[string]any)
	if got, want := jsonProps(defs["observation"].(map[string]any)), openAPIProps(t, spec, "RIDObservation"); !slices.Equal(got, want) {
		t.Errorf("observation: schema %v, contract %v", got, want)
	}
	if got, want := jsonProps(defs["position"].(map[string]any)), openAPIProps(t, spec, "RIDPosition"); !slices.Equal(got, want) {
		t.Errorf("position: schema %v, contract %v", got, want)
	}
	items := schema["properties"].(map[string]any)["observations"].(map[string]any)
	if items["maxItems"] != float64(receivers.MaxObservations) {
		t.Errorf("maxItems %v", items["maxItems"])
	}
}
