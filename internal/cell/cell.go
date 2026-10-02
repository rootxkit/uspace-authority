package cell

import (
	"slices"
	"strings"

	"github.com/rootxkit/uspace-core/core"
	"github.com/rootxkit/uspace-core/geodesy"
	"github.com/rootxkit/uspace-core/geodesy/cell"
)

// ID is a core cell.
type ID = cell.ID

// The two levels.
const (
	Level3 = cell.Level3
	Level5 = cell.Level5
)

// Of is the cell of level l that holds p (core).
func Of(p core.LatLon, l cell.Level) (ID, error) { return cell.Of(p, l) }

// Parse reads a cell name (core).
func Parse(s string) (ID, error) { return cell.Parse(s) }

// Token is the subject-token form of c's name: each ':' written '_'
// (c5_1317_2248). A NATS subject admits ':' but a KV key does not, and
// one spelling serves both. An invalid ID has the empty token.
func Token(c ID) string { return strings.ReplaceAll(c.String(), ":", "_") }

// ParseToken reads a token Token produced; every other spelling is
// refused with a *core.FieldError naming "cell", as Parse refuses names.
func ParseToken(s string) (ID, error) {
	if strings.Contains(s, ":") {
		return ID{}, core.Fieldf("cell", "%q is a cell name, not a token", s)
	}
	return cell.Parse(strings.ReplaceAll(s, "_", ":"))
}

// Tokens returns the subject tokens of p's cell3 and cell5, the two
// partition keys of a track subject (trk.v1.<cell3>.<cell5>.<id>).
func Tokens(p core.LatLon) (cell3, cell5 string, err error) {
	c5, err := cell.Of(p, cell.Level5)
	if err != nil {
		return "", "", err
	}
	return Token(c5.Parent()), Token(c5), nil
}

// DefaultViewportMax bounds the cells of one viewport.
const DefaultViewportMax = 2000

// Viewport is the set of c5 cells a console showing b subscribes to: the
// cover of b plus one ring of neighbours as the margin (05 §3), so an
// aircraft about to enter the view is already streamed. A box crossing
// the antimeridian (MinLon > MaxLon) is handled by core. More than
// maxCells cells, margin included, is refused with a *core.FieldError
// naming "bbox" and the bound (E-10). The result is sorted.
func Viewport(b geodesy.BBox, maxCells int) ([]ID, error) {
	cover, err := cell.Cover(b, cell.Level5, maxCells)
	if err != nil {
		return nil, err
	}
	set := make(map[ID]struct{}, len(cover)*2)
	for _, c := range cover {
		set[c] = struct{}{}
		for _, n := range c.Ring1() {
			set[n] = struct{}{}
		}
		if len(set) > maxCells {
			return nil, core.Fieldf("bbox", "covers more than %d cells at c5 with its one-cell margin", maxCells)
		}
	}
	out := make([]ID, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b ID) int {
		if a.LatIdx != b.LatIdx {
			return a.LatIdx - b.LatIdx
		}
		return a.LonIdx - b.LonIdx
	})
	return out, nil
}
