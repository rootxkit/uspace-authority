package corevectors

import (
	"runtime/debug"
	"testing"

	// Every core package with vectors; `make vectors` runs their tests
	// from the module cache at the pinned version.
	_ "github.com/rootxkit/uspace-core/alerting"
	_ "github.com/rootxkit/uspace-core/auth"
	_ "github.com/rootxkit/uspace-core/cpa"
	_ "github.com/rootxkit/uspace-core/ed269"
	_ "github.com/rootxkit/uspace-core/ed318"
	_ "github.com/rootxkit/uspace-core/geodesy"
	_ "github.com/rootxkit/uspace-core/geoid"
	_ "github.com/rootxkit/uspace-core/identify"
	_ "github.com/rootxkit/uspace-core/odid"
	_ "github.com/rootxkit/uspace-core/regnum"
	_ "github.com/rootxkit/uspace-core/rid"
	_ "github.com/rootxkit/uspace-core/serial"
	_ "github.com/rootxkit/uspace-core/sources"
	_ "github.com/rootxkit/uspace-core/terrain"
	_ "github.com/rootxkit/uspace-core/timeplace"
	_ "github.com/rootxkit/uspace-core/vectors"
	_ "github.com/rootxkit/uspace-core/zones"
)

// pinnedCore is the uspace-core tag this repository builds on (plan
// §13); it moves only in its own build: commit.
const pinnedCore = "v1.0.0"

func TestCoreVersionIsThePinnedTag(t *testing.T) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info in this test binary")
	}
	for _, d := range bi.Deps {
		if d.Path == "github.com/rootxkit/uspace-core" {
			if d.Replace != nil {
				t.Fatalf("uspace-core is replaced by %s: no replace, no fork (plan §13)", d.Replace.Path)
			}
			if d.Version != pinnedCore {
				t.Fatalf("uspace-core %s, want %s", d.Version, pinnedCore)
			}
			return
		}
	}
	t.Fatal("uspace-core is not a dependency of this test binary")
}
