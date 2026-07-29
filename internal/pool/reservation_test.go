package pool

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/wgtunnel"
)

const testEventTimeout = 2 * time.Second

func awaitTestEvent[T any](t *testing.T, events <-chan T) T {
	t.Helper()
	select {
	case event := <-events:
		return event
	case <-time.After(testEventTimeout):
		t.Fatal("timed out waiting for concurrent test event")
		var zero T
		return zero
	}
}

func TestAcquireReservesConnectionCapacityBeforeDial(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		wantErr error
	}{
		{
			name:    "global limit",
			options: Options{MaxConcurrentConns: 1, DialAttempts: 1},
			wantErr: ErrBusy,
		},
		{
			name:    "per-exit limit",
			options: Options{MaxConnsPerExit: 1, DialAttempts: 1},
			wantErr: ErrNoCandidate,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPool(t, tt.options)
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			p.ensureDialerForAcquire = func(context.Context, *slotState) (Dialer, string, error) {
				entered <- struct{}{}
				<-release
				return &net.Dialer{}, "", nil
			}

			results := make(chan error, 2)
			acquire := func() {
				lease, err := p.Acquire(
					context.Background(),
					policy.Policy{Slot: "jp-tyo-wg-001"},
					"example.com",
				)
				if lease != nil {
					lease.Release()
				}
				results <- err
			}

			go acquire()
			awaitTestEvent(t, entered)
			go acquire()

			select {
			case <-entered:
				close(release)
				t.Fatal("second Acquire crossed the pending connection limit")
			case err := <-results:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("second Acquire error = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(testEventTimeout):
				t.Fatal("timed out waiting for second Acquire result")
			}
			close(release)
			if err := awaitTestEvent(t, results); err != nil {
				t.Fatalf("first Acquire: %v", err)
			}
		})
	}
}

func TestAcquireReservesTunnelCapacityBeforeOpen(t *testing.T) {
	tests := []struct {
		name    string
		options Options
		wantErr error
	}{
		{
			name:    "active tunnel limit",
			options: Options{MaxActive: 1, DialAttempts: 1},
			wantErr: ErrCapacity,
		},
		{
			name: "new tunnel budget",
			options: Options{
				NewTunnelBudget: 1,
				NewTunnelWindow: time.Hour,
				DialAttempts:    1,
			},
			wantErr: ErrTunnelBudget,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestPool(t, tt.options)
			picked := make(chan struct{}, 2)
			releasePicks := make(chan struct{})
			p.ensureDialerForAcquire = func(ctx context.Context, state *slotState) (Dialer, string, error) {
				picked <- struct{}{}
				<-releasePicks
				return p.ensureDialer(ctx, state)
			}

			opening := make(chan string, 2)
			releaseOpen := make(chan struct{})
			openErr := errors.New("test open stopped")
			p.openTunnelForCapacity = func(
				_ context.Context,
				spec catalog.Slot,
				_ TunnelRole,
			) (*wgtunnel.Tunnel, error) {
				opening <- spec.ID
				<-releaseOpen
				return nil, openErr
			}

			results := make(chan error, 2)
			acquire := func(slot string) {
				_, err := p.Acquire(
					context.Background(),
					policy.Policy{Slot: slot},
					"example.com",
				)
				results <- err
			}

			go acquire("jp-tyo-wg-001")
			go acquire("us-lax-wg-001")
			awaitTestEvent(t, picked)
			awaitTestEvent(t, picked)
			close(releasePicks)
			awaitTestEvent(t, opening)

			select {
			case slot := <-opening:
				close(releaseOpen)
				t.Fatalf("second Acquire opened %s beyond the pending tunnel limit", slot)
			case err := <-results:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("second Acquire error = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(testEventTimeout):
				t.Fatal("timed out waiting for second tunnel result")
			}
			close(releaseOpen)
			if err := awaitTestEvent(t, results); !errors.Is(err, openErr) {
				t.Fatalf("first Acquire error = %v, want %v", err, openErr)
			}
		})
	}
}

func TestMaxActiveCountsEntryOpenings(t *testing.T) {
	p := newRelayPool(t, Options{MaxActive: 1, DialAttempts: 1})
	entered := make(chan string, 2)
	release := make(chan struct{})
	openErr := errors.New("test entry open stopped")
	p.openTunnelForCapacity = func(
		_ context.Context,
		spec catalog.Slot,
		_ TunnelRole,
	) (*wgtunnel.Tunnel, error) {
		entered <- spec.ID
		<-release
		return nil, openErr
	}

	results := make(chan error, 2)
	for _, entry := range p.entries[:2] {
		go func(entry *entryState) {
			_, err := p.ensureEntryOpen(context.Background(), entry)
			results <- err
		}(entry)
		if entry == p.entries[0] {
			awaitTestEvent(t, entered)
		}
	}

	select {
	case entryID := <-entered:
		close(release)
		t.Fatalf("second entry %s opened beyond MaxActive", entryID)
	case err := <-results:
		if !errors.Is(err, ErrCapacity) {
			t.Fatalf("second entry error = %v, want %v", err, ErrCapacity)
		}
	case <-time.After(testEventTimeout):
		t.Fatal("timed out waiting for second entry result")
	}
	close(release)
	if err := awaitTestEvent(t, results); !errors.Is(err, openErr) {
		t.Fatalf("first entry error = %v, want %v", err, openErr)
	}
}

func TestMaxActiveBlocksProbeDuringEntryOpen(t *testing.T) {
	p := newRelayPool(t, Options{MaxActive: 1, DialAttempts: 1})
	entered := make(chan string, 2)
	release := make(chan struct{})
	openErr := errors.New("test tunnel open stopped")
	p.openTunnelForCapacity = func(
		_ context.Context,
		spec catalog.Slot,
		_ TunnelRole,
	) (*wgtunnel.Tunnel, error) {
		entered <- spec.ID
		<-release
		return nil, openErr
	}

	entryResult := make(chan error, 1)
	go func() {
		_, err := p.ensureEntryOpen(context.Background(), p.entries[0])
		entryResult <- err
	}()
	awaitTestEvent(t, entered)

	probeState := &slotState{
		spec: Spec{
			ID:   "probe-wg-001",
			Kind: KindWireGuard,
			WG:   testEntrySlots()[1],
		},
	}
	probeResult := make(chan error, 1)
	go func() {
		_, _, err := p.probeDialer(context.Background(), probeState)
		probeResult <- err
	}()

	select {
	case probeID := <-entered:
		close(release)
		t.Fatalf("probe %s opened beyond MaxActive", probeID)
	case err := <-probeResult:
		if !errors.Is(err, ErrCapacity) {
			t.Fatalf("probe error = %v, want %v", err, ErrCapacity)
		}
	case <-time.After(testEventTimeout):
		t.Fatal("timed out waiting for probe result")
	}
	close(release)
	if err := awaitTestEvent(t, entryResult); !errors.Is(err, openErr) {
		t.Fatalf("entry error = %v, want %v", err, openErr)
	}
}

func TestProbeRollsBackCapacityAfterOpenFailure(t *testing.T) {
	p := newTestPool(t, Options{
		MaxActive:       1,
		NewTunnelBudget: 1,
		NewTunnelWindow: time.Hour,
	})
	openErr := errors.New("test probe open failed")
	p.openTunnelForCapacity = func(
		context.Context,
		catalog.Slot,
		TunnelRole,
	) (*wgtunnel.Tunnel, error) {
		return nil, openErr
	}

	_, _, err := p.probeDialer(
		context.Background(),
		p.slots["jp-tyo-wg-001"],
	)
	if !errors.Is(err, openErr) {
		t.Fatalf("probe error = %v, want %v", err, openErr)
	}

	p.mu.Lock()
	probeTunnels := p.probeTunnels
	p.mu.Unlock()
	if probeTunnels != 0 {
		t.Fatalf("probe capacity after failure = %d, want zero", probeTunnels)
	}
}

func TestAcquireRollsBackPendingLeaseAfterDialFailure(t *testing.T) {
	p := newTestPool(t, Options{MaxConcurrentConns: 1, DialAttempts: 1})
	dialErr := errors.New("test dial failed")
	calls := 0
	p.ensureDialerForAcquire = func(context.Context, *slotState) (Dialer, string, error) {
		calls++
		if calls == 1 {
			return nil, "", dialErr
		}
		return &net.Dialer{}, "", nil
	}

	_, err := p.Acquire(
		context.Background(),
		policy.Policy{Slot: "jp-tyo-wg-001"},
		"example.com",
	)
	if !errors.Is(err, dialErr) {
		t.Fatalf("first Acquire error = %v, want %v", err, dialErr)
	}
	lease, err := p.Acquire(
		context.Background(),
		policy.Policy{Slot: "us-lax-wg-001"},
		"example.com",
	)
	if err != nil {
		t.Fatalf("second Acquire: %v", err)
	}
	lease.Release()

	p.mu.Lock()
	pending := p.pendingLeases
	slotPending := p.slots["jp-tyo-wg-001"].pendingLeases
	p.mu.Unlock()
	if pending != 0 || slotPending != 0 {
		t.Fatalf("pending leases = pool %d slot %d, want zero", pending, slotPending)
	}
}

func TestAcquireRollsBackPendingReservationsWhenCanceled(t *testing.T) {
	p := newTestPool(t, Options{
		MaxActive:          1,
		MaxConcurrentConns: 1,
		NewTunnelBudget:    1,
		NewTunnelWindow:    time.Hour,
		DialAttempts:       1,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := p.Acquire(
		ctx,
		policy.Policy{Slot: "jp-tyo-wg-001"},
		"example.com",
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire error = %v, want context canceled", err)
	}

	p.mu.Lock()
	pendingLeases := p.pendingLeases
	pendingOpens := p.pendingTunnelOpens
	opening := p.slots["jp-tyo-wg-001"].opening
	opens := len(p.opens)
	p.mu.Unlock()
	if pendingLeases != 0 || pendingOpens != 0 || opening != nil || opens != 0 {
		t.Fatalf(
			"pending state = leases %d opens %d opening %v committed %d",
			pendingLeases,
			pendingOpens,
			opening != nil,
			opens,
		)
	}
}
