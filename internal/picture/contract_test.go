package picture

import (
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
)

// The picture operations are the same three in the contract
// (x-picture), in apiserver.Picture and in the generator's exclusions,
// each served here on the contract's method and path, and none has a
// rule of api's (they never reach Authorize).
func TestPictureOperationsMatchTheContract(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	pathRe := regexp.MustCompile(`^  (/\S+):$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|patch|delete):$`)
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	ops := map[string]string{}
	var path, method, op string
	for line := range strings.SplitSeq(string(raw), "\n") {
		if m := pathRe.FindStringSubmatch(line); m != nil {
			path = m[1]
		}
		if m := methodRe.FindStringSubmatch(line); m != nil {
			method = strings.ToUpper(m[1])
		}
		if m := opRe.FindStringSubmatch(line); m != nil {
			op = strings.ToUpper(m[1][:1]) + m[1][1:]
		}
		if strings.TrimSpace(line) == "x-picture: true" {
			ops[op] = method + " " + path
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(ops)), slices.Sorted(maps.Keys(apiserver.Picture))) {
		t.Fatalf("contract %v, apiserver.Picture %v", ops, apiserver.Picture)
	}
	served := map[string]string{"GetPictureWS": PatternWS, "GetPictureSnapshot": PatternSnapshot, "GetPictureSources": PatternSources}
	for op, want := range ops {
		if served[op] != want {
			t.Errorf("%s served on %q, the contract says %q", op, served[op], want)
		}
		if _, ok := apiserver.Roles[op]; ok || apiserver.Public[op] || apiserver.AnySession[op] || apiserver.Scopes[op] != "" {
			t.Errorf("%s has a rule of api's", op)
		}
	}
	cfg, err := os.ReadFile("../../api/oapi-codegen.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for op := range ops {
		if !strings.Contains(string(cfg), strings.ToLower(op[:1])+op[1:]) {
			t.Errorf("%s is not excluded from the generated server", op)
		}
	}
}
