package picture

import (
	"testing"

	"github.com/rootxkit/uspace-authority/internal/dpviews"
)

// WP-14: a console that subscribed reports its viewport (snapped
// outwards, once however many consoles show it); one that has not
// subscribed reports nothing; past the bound the rest are counted.
func TestViewportsOfTheSubscribedConsoles(t *testing.T) {
	h := testHub(t, nil)
	idle := connect(t, h, consoleSession(), nil)
	_ = idle
	if boxes, over := h.Viewports(10); len(boxes) != 0 || over != 0 {
		t.Fatalf("an idle console reported %v", boxes)
	}
	a := connect(t, h, consoleSession(), nil)
	subscribe(t, a, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	b := connect(t, h, consoleSession(), nil)
	subscribe(t, b, subscribeFrameOf(44.80, 41.70, 44.85, 41.73))
	c := connect(t, h, consoleSession(), nil)
	subscribe(t, c, subscribeFrameOf(44.70, 41.60, 44.75, 41.65))
	boxes, over := h.Viewports(10)
	if len(boxes) != 2 || over != 0 {
		t.Fatalf("viewports %v over %d", boxes, over)
	}
	for _, bx := range boxes {
		if bx.Check() != nil {
			t.Fatalf("%v is not a usable box", bx)
		}
	}
	want := dpviews.Round(dpviews.BBox{44.80, 41.70, 44.85, 41.73})
	if boxes[0] != want && boxes[1] != want {
		t.Fatalf("viewports %v, want %v among them", boxes, want)
	}
	if boxes, over := h.Viewports(1); len(boxes) != 1 || over != 1 {
		t.Fatalf("bound: %v over %d", boxes, over)
	}
}
