package picture

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// heldConn is a fakeConn whose next write, once armed, is held in flight
// until released or until its context ends, and which records whether
// that write's context had ended when Close was called. The WebSocket
// library drops the connection when a write's context ends, so a held
// write whose context ended before Close stands for a close frame that
// never reached the console.
type heldConn struct {
	*fakeConn
	arm      atomic.Bool
	inFlight chan context.Context
	release  chan struct{}
	freed    sync.Once
	held     atomic.Pointer[context.Context]
	// errAtClose is the held write's ctx.Err() when Close was called.
	errAtClose atomic.Pointer[error]
}

func newHeldConn() *heldConn {
	return &heldConn{fakeConn: newFakeConn(4096), inFlight: make(chan context.Context, 1), release: make(chan struct{})}
}

func (c *heldConn) Write(ctx context.Context, f []byte) error {
	if !c.arm.CompareAndSwap(true, false) {
		return c.fakeConn.Write(ctx, f)
	}
	c.held.Store(&ctx)
	c.inFlight <- ctx
	select {
	case <-c.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// free releases the held write; idempotent.
func (c *heldConn) free() { c.freed.Do(func() { close(c.release) }) }

func (c *heldConn) Close(code websocket.StatusCode, reason string) error {
	if p := c.held.Load(); p != nil {
		err := (*p).Err()
		c.errAtClose.CompareAndSwap(nil, &err)
	}
	return c.fakeConn.Close(code, reason)
}

// serveHeld attaches a console on a heldConn, reads its status and
// snapshot, and returns it with a write held in flight: the status that
// answers a subscription.
func serveHeld(t *testing.T, h *Hub) (*heldConn, context.Context) {
	t.Helper()
	conn := newHeldConn()
	if !h.Reserve() {
		t.Fatal("hub full")
	}
	served := make(chan struct{})
	go func() { defer close(served); h.Serve(conn, consoleSession(), "token", nil) }()
	t.Cleanup(func() { <-served })
	t.Cleanup(conn.free) // runs first: a failed test never leaves Serve waiting
	if f, _ := conn.next(t, 2*time.Second); f.Schema != SchemaStatus {
		t.Fatalf("first frame %s, want %s", f.Schema, SchemaStatus)
	}
	if f, _ := conn.next(t, 2*time.Second); f.Schema != SchemaSnapshot {
		t.Fatalf("second frame %s, want %s", f.Schema, SchemaSnapshot)
	}
	conn.arm.Store(true)
	conn.in <- subscribeFrameOf(44.80, 41.70, 44.85, 41.73)
	select {
	case ctx := <-conn.inFlight:
		return conn, ctx
	case <-time.After(2 * time.Second):
		t.Fatal("no write in flight within 2s of the subscription")
	}
	return nil, nil
}

// waitHeldClosed waits for conn's Close and returns its code and reason.
func waitHeldClosed(t *testing.T, conn *heldConn, d time.Duration) (websocket.StatusCode, string) {
	t.Helper()
	select {
	case <-conn.closed:
	case <-time.After(d):
		t.Fatalf("not closed within %s", d)
	}
	code, reason, _ := conn.closeCode()
	return code, reason
}

// An invalid frame that arrives while a write is in flight closes the
// console with 1007, and that write's context is still live when the
// close is sent: detaching never cancels a write, so the library does
// not drop the connection before the close frame (the CI flake of
// TestBinaryFrameRefused, which saw -1 and EOF instead of 1007).
func TestDetachLeavesTheWriteInFlightToFinish(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.WriteTimeout = time.Hour, time.Minute })
	conn, wctx := serveHeld(t, h)
	conn.in <- []byte("binary")
	code, reason := waitHeldClosed(t, conn, 2*time.Second)
	conn.free()
	if code != CloseInvalid {
		t.Fatalf("closed %d %q, want %d", code, reason, CloseInvalid)
	}
	p := conn.errAtClose.Load()
	if p == nil {
		t.Fatal("Close was called with no held write recorded")
	}
	if *p != nil {
		t.Fatalf("the write in flight had its context ended (%v) before the close frame was sent", *p)
	}
	if err := wctx.Err(); err != nil {
		t.Fatalf("the write in flight was cancelled by the detach: %v", err)
	}
}

// Beside it: a write in flight that the console never takes still ends
// at WriteTimeout, and the console is closed 1001 "write failed".
func TestWriteInFlightStillEndsAtWriteTimeout(t *testing.T) {
	h := testHub(t, func(c *Config, _ *Inputs) { c.StatusInterval, c.WriteTimeout = time.Hour, 50*time.Millisecond })
	conn, wctx := serveHeld(t, h)
	code, reason := waitHeldClosed(t, conn, 2*time.Second)
	if code != CloseGoingAway || reason != "write failed" {
		t.Fatalf("closed %d %q, want %d %q", code, reason, CloseGoingAway, "write failed")
	}
	if err := wctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("held write's context: %v, want %v", err, context.DeadlineExceeded)
	}
	if n := h.Counters().Get(CounterClosedWriteFailed); n != 1 {
		t.Fatalf("%s = %d, want 1", CounterClosedWriteFailed, n)
	}
}
