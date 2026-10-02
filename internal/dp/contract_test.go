package dp

import (
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rootxkit/uspace-authority/internal/apiserver"
)

// The operations dp-poller serves are the same three in the contract
// (x-dp), in apiserver.DisplayProvider and in the generator's
// exclusions, each served here on the contract's method and path, and
// none has a rule of api's (they never reach Authorize).
func TestDisplayProviderOperationsMatchTheContract(t *testing.T) {
	spec := read(t, "../../api/openapi.yaml")
	pathRe := regexp.MustCompile(`^  (/\S+):$`)
	methodRe := regexp.MustCompile(`^    (get|post|put|patch|delete):$`)
	opRe := regexp.MustCompile(`^\s+operationId:\s*(\w+)`)
	ops := map[string]string{}
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
		if strings.TrimSpace(line) == "x-dp: true" {
			ops[op] = method + " " + path
		}
	}
	if !slices.Equal(slices.Sorted(maps.Keys(ops)), slices.Sorted(maps.Keys(apiserver.DisplayProvider))) {
		t.Fatalf("contract %v, apiserver.DisplayProvider %v", ops, apiserver.DisplayProvider)
	}
	served := map[string]string{
		"GetDPDisplayData": PatternDisplayData, "GetDPFlightDetails": PatternDisplayDetails, "PostDPISANotification": PatternNotification,
	}
	for op, want := range ops {
		if served[op] != want {
			t.Errorf("%s served on %q, the contract says %q", op, served[op], want)
		}
		if _, ok := apiserver.Roles[op]; ok || apiserver.Public[op] || apiserver.AnySession[op] || apiserver.Scopes[op] != "" {
			t.Errorf("%s has a rule of api's", op)
		}
	}
	cfg := read(t, "../../api/oapi-codegen.yaml")
	for op := range ops {
		if !strings.Contains(cfg, strings.ToLower(op[:1])+op[1:]) {
			t.Errorf("%s is not excluded from the generated server", op)
		}
	}
	// The F3411 path is the standard's own (dss-rid.yaml).
	if !strings.Contains(read(t, "../../api/clients/dss-rid.yaml"), "\n  /uss/identification_service_areas/{id}:\n") {
		t.Error("the notification path is not the pinned standard's")
	}
}
