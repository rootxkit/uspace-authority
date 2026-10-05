package ltest

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
)

// FailedLogLines is how many of each process's last log lines a failed
// scenario keeps beside its result.
const FailedLogLines = 400

// CoreModule is the shared library whose version every result names.
const CoreModule = "github.com/rootxkit/uspace-core"

// Commits name what a result measured (LESSONS E-05): this repository's
// commit and the uspace-core version the test binary was built with.
type Commits struct {
	Authority string `json:"uspace-authority"`
	Core      string `json:"uspace-core"`
}

// CurrentCommits reads git (with "+dirty" when the working tree has
// changes), or GITHUB_SHA when git cannot be run, and the build
// information of the test binary. Neither is ever guessed: what cannot
// be read says so. In CI the job compares the commit read here with
// GITHUB_SHA.
func CurrentCommits() Commits {
	c := Commits{Authority: "unknown", Core: "unknown"}
	root := repoRoot()
	out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output() //nolint:gosec // fixed arguments; root is this module's own directory
	switch {
	case err == nil:
		c.Authority = strings.TrimSpace(string(out))
		st, err := exec.Command("git", "-C", root, "status", "--porcelain").Output() //nolint:gosec // as above
		if err == nil && len(strings.TrimSpace(string(st))) > 0 {
			c.Authority += "+dirty"
		}
	case os.Getenv("GITHUB_SHA") != "":
		c.Authority = os.Getenv("GITHUB_SHA") + " (GITHUB_SHA; git: " + err.Error() + ")"
	default:
		c.Authority = "unknown: " + err.Error()
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == CoreModule {
				c.Core = d.Version
				if d.Sum != "" {
					c.Core += " " + d.Sum
				}
				if d.Replace != nil {
					c.Core += " replaced by " + d.Replace.Path + " " + d.Replace.Version
				}
			}
		}
	}
	return c
}

// Result is one scenario's results file.
type Result struct {
	Scenario   string                                  `json:"scenario"`
	Test       string                                  `json:"test"`
	Passed     bool                                    `json:"passed"`
	StartedAt  time.Time                               `json:"started_at"`
	FinishedAt time.Time                               `json:"finished_at"`
	Commits    Commits                                 `json:"commits"`
	Report     *Report                                 `json:"report"`
	Status     map[string]map[string]map[string]uint64 `json:"status"`
	// LogLinesDropped and RecorderDropped are the harness's own bounds
	// exceeded (nothing it read was lost silently either).
	LogLinesDropped map[string]int `json:"log_lines_dropped"`
	RecorderDropped map[string]int `json:"recorder_dropped"`
	Notes           map[string]any `json:"notes"`
}

// writeResults writes the result as <dir>/<scenario>.json; it runs when
// the test ends, after its processes stopped.
func (s *Stack) writeResults() {
	s.mu.Lock()
	procs := append([]*Proc(nil), s.procs...)
	res := Result{Scenario: s.Name, Test: s.T.Name(), Passed: !s.T.Failed(), StartedAt: s.started, FinishedAt: time.Now().UTC(),
		Commits: CurrentCommits(), Report: s.verified, Status: map[string]map[string]map[string]uint64{},
		LogLinesDropped: map[string]int{}, Notes: s.extra}
	s.mu.Unlock()
	for _, p := range procs {
		p.Stop()
		res.Status[p.Name] = p.Counters()
		res.LogLinesDropped[p.Name] = p.Out.Dropped()
	}
	if s.Rec != nil {
		res.RecorderDropped = s.Rec.Dropped()
	}
	dir := resultsDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.T.Errorf("ltest: results directory %s: %v", dir, err)
		return
	}
	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		s.T.Errorf("ltest: results: %v", err)
		return
	}
	// A failed scenario keeps each process's last lines beside its
	// result, so a CI failure can be read without a rerun.
	if !res.Passed {
		for _, p := range procs {
			lp := filepath.Join(dir, token(s.Name)+"."+p.Name+".log")
			if err := os.WriteFile(lp, []byte(p.Out.Tail(FailedLogLines)+"\n"), 0o600); err != nil {
				s.T.Errorf("ltest: log %s: %v", lp, err)
			}
		}
	}
	path := filepath.Join(dir, token(s.Name)+".json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		s.T.Errorf("ltest: results %s: %v", path, err)
		return
	}
	// Read back (E-04): a results file that does not parse is not a
	// result.
	var back Result
	b, err := os.ReadFile(path) //nolint:gosec // the file written just above
	if err != nil || json.Unmarshal(b, &back) != nil || back.Scenario != s.Name {
		s.T.Errorf("ltest: results %s did not read back", path)
		return
	}
	s.T.Logf("results: %s (passed %v, uspace-authority %s, uspace-core %s)", path, res.Passed, res.Commits.Authority, res.Commits.Core)
}
