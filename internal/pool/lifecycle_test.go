package pool

import (
	"runtime"
	"testing"
	"time"
)

// The pool starts goroutines for tunnel teardown and public-IP checks. Close must
// wait for them, or a long-lived process leaks one set per pool it creates.
func TestCloseWaitsForOwnedGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()

	for range 20 {
		p := newRelayPool(t, Options{})
		// Start background work of the kind Close has to account for.
		p.background(func() { time.Sleep(20 * time.Millisecond) })
		p.Close()
		// A second Close must be a no-op rather than a panic on a closed channel.
		p.Close()
	}

	// Allow the runtime a moment to reap anything already returned.
	time.Sleep(50 * time.Millisecond)
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Errorf("goroutines grew from %d to %d across 20 pool lifecycles", before, after)
	}
}

func TestBackgroundRefusedAfterClose(t *testing.T) {
	p := newRelayPool(t, Options{})
	p.Close()
	if p.background(func() { t.Error("background work ran after Close") }) {
		t.Error("background reported success after Close")
	}
}
