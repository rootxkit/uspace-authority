package ltest

import (
	"sync"
	"time"
)

// Flight is a receiver hearing a set of aircraft step by step in the
// background, one step per Period (1 Hz), until Stop.
type Flight struct {
	r    *Receiver
	acs  []*Aircraft
	stop chan struct{}
	done chan struct{}

	mu      sync.Mutex
	step    int
	changed chan struct{}
	once    sync.Once
}

// Fly starts hearing acs at once (step 0 now) and every Period after.
// The flight stops at the end of the test if Stop was not called.
func (r *Receiver) Fly(acs ...*Aircraft) *Flight {
	f := &Flight{r: r, acs: acs, stop: make(chan struct{}), done: make(chan struct{}), changed: make(chan struct{})}
	go f.run()
	r.s.T.Cleanup(f.Stop)
	return f
}

func (f *Flight) run() {
	defer close(f.done)
	// Steps are heard just after a tenth of a second (the Location
	// timestamp's resolution), so a broadcast time is at most a few
	// milliseconds before it was heard and a placement can be checked to
	// the tenth (SC-11).
	now := time.Now()
	start := now.Truncate(100 * time.Millisecond).Add(105 * time.Millisecond)
	select {
	case <-f.stop:
		return
	case <-time.After(start.Sub(now)):
	}
	tick := time.NewTicker(f.r.period())
	defer tick.Stop()
	for {
		f.mu.Lock()
		step := f.step
		f.mu.Unlock()
		if err := f.r.Step(step, f.acs...); err != nil {
			f.r.s.T.Errorf("ltest: %v", err)
			return
		}
		f.mu.Lock()
		f.step++
		close(f.changed)
		f.changed = make(chan struct{})
		f.mu.Unlock()
		select {
		case <-f.stop:
			return
		case <-tick.C:
		}
	}
}

// Steps is how many steps have been sent.
func (f *Flight) Steps() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.step
}

// WaitSteps blocks until n more steps have been sent, failing the test
// if they take more than twice their period plus 10 s.
func (f *Flight) WaitSteps(n int) {
	f.r.s.T.Helper()
	f.mu.Lock()
	target := f.step + n
	f.mu.Unlock()
	f.waitUntil(target)
}

// WaitStep blocks until step k has been sent.
func (f *Flight) WaitStep(k int) {
	f.r.s.T.Helper()
	f.waitUntil(k + 1)
}

func (f *Flight) waitUntil(target int) {
	f.r.s.T.Helper()
	f.mu.Lock()
	missing := target - f.step
	f.mu.Unlock()
	deadline := time.NewTimer(time.Duration(2*max(missing, 0))*f.r.period() + 10*time.Second)
	defer deadline.Stop()
	for {
		f.mu.Lock()
		if f.step >= target {
			f.mu.Unlock()
			return
		}
		ch := f.changed
		f.mu.Unlock()
		select {
		case <-ch:
		case <-f.done:
			f.r.s.T.Fatalf("ltest: flight of %s stopped before step %d", f.r.ID, target-1)
		case <-deadline.C:
			f.r.s.T.Fatalf("ltest: flight of %s did not reach step %d", f.r.ID, target-1)
		}
	}
}

// Stop ends the flight after the step in progress and delivers every
// batch still waiting for its latency, each when it is due, so the
// tally is complete and no batch arrives earlier than its latency.
func (f *Flight) Stop() {
	f.once.Do(func() {
		close(f.stop)
		<-f.done
		f.r.drain()
	})
}
