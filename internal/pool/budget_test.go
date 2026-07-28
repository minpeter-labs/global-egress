package pool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/policy"
)

// The provider restricts how quickly one device key may associate with new
// relays. These tests cover the budget that keeps us under that limit; they never
// dial, because the budget is checked before any tunnel is opened.

func TestTunnelBudgetBlocksNewTunnels(t *testing.T) {
	p := newTestPool(t, Options{NewTunnelBudget: 2, NewTunnelWindow: time.Hour})

	// Simulate two tunnel openings.
	now := time.Now()
	p.noteTunnelOpen(now)
	p.noteTunnelOpen(now)

	// Nothing is open, so serving a request would require opening a third.
	_, err := p.Acquire(context.Background(), policy.Policy{}, "example.com")
	if !errors.Is(err, ErrTunnelBudget) {
		t.Fatalf("error = %v, want ErrTunnelBudget", err)
	}

	stats := p.Stats()
	if stats.NewTunnelsUsed != 2 || stats.NewTunnelBudget != 2 {
		t.Errorf("stats = used %d / budget %d, want 2 / 2",
			stats.NewTunnelsUsed, stats.NewTunnelBudget)
	}
	if stats.NewTunnelWindow != "1h0m0s" {
		t.Errorf("NewTunnelWindow = %q", stats.NewTunnelWindow)
	}
}

func TestTunnelBudgetWindowRolls(t *testing.T) {
	p := newTestPool(t, Options{NewTunnelBudget: 1, NewTunnelWindow: time.Minute})

	// An opening from before the window must not count against it.
	p.noteTunnelOpen(time.Now().Add(-2 * time.Minute))

	p.mu.Lock()
	available := p.tunnelBudgetAvailableLocked(time.Now())
	remaining := len(p.opens)
	p.mu.Unlock()

	if !available {
		t.Error("budget should be available again once the window has rolled")
	}
	if remaining != 0 {
		t.Errorf("stale openings were not pruned: %d remain", remaining)
	}
}

func TestZeroBudgetMeansUnlimited(t *testing.T) {
	p := newTestPool(t, Options{NewTunnelBudget: 0})
	now := time.Now()
	for range 50 {
		p.noteTunnelOpen(now)
	}
	p.mu.Lock()
	available := p.tunnelBudgetAvailableLocked(now)
	p.mu.Unlock()
	if !available {
		t.Error("a zero budget must not limit anything")
	}
}

func TestWarmupRespectsBudget(t *testing.T) {
	p := newTestPool(t, Options{NewTunnelBudget: 3, NewTunnelWindow: time.Hour})
	now := time.Now()
	p.noteTunnelOpen(now)
	p.noteTunnelOpen(now)
	p.noteTunnelOpen(now)

	// The budget is spent, so Warmup must not attempt any tunnel at all. If it
	// did, it would block on dialling unreachable test endpoints.
	done := make(chan int, 1)
	go func() { done <- p.Warmup(context.Background(), 5) }()
	select {
	case opened := <-done:
		if opened != 0 {
			t.Errorf("Warmup opened %d tunnels despite an exhausted budget", opened)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Warmup ignored the budget and tried to dial")
	}
}

func TestBudgetDoesNotBlockAlreadyOpenTunnels(t *testing.T) {
	p := newTestPool(t, Options{NewTunnelBudget: 1, NewTunnelWindow: time.Hour})
	now := time.Now()
	p.noteTunnelOpen(now)

	// Pretend one slot is already up. Selection must prefer it and succeed even
	// though the rate budget is spent: reusing a tunnel contacts no new relay.
	p.mu.Lock()
	state := p.slots["jp-tyo-wg-001"]
	state.tunnel = nil // no real device; eligibility is what we assert below
	eligible := p.eligibleLocked(state, policy.Policy{}, "example.com", now)
	budgetLeft := p.tunnelBudgetAvailableLocked(now)
	p.mu.Unlock()

	if !eligible {
		t.Error("slot should still be eligible; the budget only gates new tunnels")
	}
	if budgetLeft {
		t.Error("budget should be reported as exhausted")
	}
}
