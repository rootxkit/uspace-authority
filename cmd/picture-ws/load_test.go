package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/metrics"
	"strconv"
	"testing"
	"time"

	"github.com/rootxkit/uspace-authority/internal/picture"
)

// cpuSeconds is the CPU the process's Go code has used so far, total
// less idle (the runtime's estimate, runtime/metrics).
func cpuSeconds() float64 {
	s := []metrics.Sample{{Name: "/cpu/classes/total:cpu-seconds"}, {Name: "/cpu/classes/idle:cpu-seconds"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindFloat64 || s[1].Value.Kind() != metrics.KindFloat64 {
		return 0
	}
	return s[0].Value.Float64() - s[1].Value.Float64()
}

// The load smoke of WP-13 (05 §1: 2000 msg/s out at 100 drones): 10
// consoles on one viewport, 200 tracks at 1 Hz for PICTURE_LOAD_S
// seconds (60 by default). It reports the frames per second the consoles
// received and the CPU of the whole test process (picture-ws, the
// publisher and the ten consoles together: an upper bound). Run with
// INTEGRATION=1 PICTURE_LOAD=1; it is not part of the integration job.
func TestLoadSmokeTenConsoles200TracksAt1Hz(t *testing.T) {
	if os.Getenv("PICTURE_LOAD") != "1" {
		t.Skip("PICTURE_LOAD=1 not set: the 60 s load smoke runs on demand")
	}
	nc, _ := connectNATS(t)
	api := newSessionAPI(t)
	p := startPicture(t, api, natsURL(t), nil)
	seconds := 60
	if v, err := strconv.Atoi(os.Getenv("PICTURE_LOAD_S")); err == nil && v > 0 {
		seconds = v
	}
	consoles := make([]*console, 10)
	for i := range consoles {
		c := dialConsole(t, p.ws, api.session(t, fmt.Sprintf("load-%d", i)), 0)
		c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
		c.subscribe(t, 44.70, 41.65, 44.95, 41.80)
		c.until(t, picture.SchemaSnapshot, 5*time.Second, nil)
		consoles[i] = c
	}
	counts := make([]chan int, len(consoles))
	stop := make(chan struct{})
	for i, c := range consoles {
		counts[i] = make(chan int, 1)
		go func() {
			n := 0
			for {
				select {
				case <-stop:
					counts[i] <- n
					return
				case raw, ok := <-c.frames:
					if !ok {
						counts[i] <- n
						return
					}
					var e envelope
					if json.Unmarshal(raw, &e) == nil && e.Schema == picture.SchemaTrack {
						n++
					}
				}
			}
		}()
	}
	cpu0, start := cpuSeconds(), time.Now()
	tick := time.NewTicker(time.Second)
	for s := range seconds {
		now := time.Now()
		for i := range 200 {
			publishTrack(t, nc, fmt.Sprintf("load-%03d", i), 41.66+float64(i/20)*0.012, 44.71+float64(i%20)*0.011, now)
		}
		if s < seconds-1 {
			<-tick.C
		}
	}
	tick.Stop()
	if err := nc.Flush(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	elapsed, cpu := time.Since(start).Seconds(), cpuSeconds()-cpu0
	close(stop)
	total := 0
	for _, c := range counts {
		total += <-c
	}
	var dropped uint64
	for _, c := range consoles {
		st := statusBody(t, c.until(t, picture.SchemaStatus, 5*time.Second, nil))
		dropped += st.DroppedFrames
	}
	t.Logf("load smoke: %d consoles x 200 tracks at 1 Hz for %d s: %d track frames received, %.0f frames/s out, dropped_frames %d, CPU %.1f s in %.1f s (%.0f %% of one core, the whole test process)",
		len(consoles), seconds, total, float64(total)/elapsed, dropped, cpu, elapsed, 100*cpu/elapsed)
	if want := len(consoles) * 200 * seconds; total < want*95/100 {
		t.Fatalf("received %d of %d frames", total, want)
	}
}
