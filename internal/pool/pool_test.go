package pool

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/minpeter/global-egress/internal/catalog"
	"github.com/minpeter/global-egress/internal/policy"
)

// testBundle builds a bundle without touching the network. The keys are
// syntactically valid but never used, because these tests exercise selection
// bookkeeping only: anything that would dial is arranged to fail earlier.
func testBundle(t *testing.T) *catalog.Bundle {
	t.Helper()
	specs := []struct{ id, country, city string }{
		{"jp-tyo-wg-001", "jp", "jp-tyo"},
		{"jp-osa-wg-001", "jp", "jp-osa"},
		{"us-lax-wg-001", "us", "us-lax"},
		{"us-lax-wg-002", "us", "us-lax"},
		{"de-fra-wg-001", "de", "de-fra"},
	}
	bundle := &catalog.Bundle{DistinctKeys: 1}
	for i, spec := range specs {
		bundle.Slots = append(bundle.Slots, catalog.Slot{
			ID:            spec.id,
			Country:       spec.country,
			City:          spec.city,
			PrivateKey:    "R0xPQkFMLUVHUkVTUy1URVNULUtFWS1OT1QtUkVBTCE=",
			PeerPublicKey: "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=",
			Addresses:     []netip.Addr{netip.MustParseAddr("10.64.0.2")},
			Endpoint:      netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(51820+i)).String(),
			MTU:           catalog.DefaultMTU,
		})
	}
	return bundle
}

func newTestPool(t *testing.T, opts Options) *Pool {
	t.Helper()
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Rand == nil {
		opts.Rand = rand.New(rand.NewPCG(1, 1))
	}
	p, err := New(testBundle(t), opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestNewRejectsEmptyBundle(t *testing.T) {
	if _, err := New(&catalog.Bundle{}, Options{}); err == nil {
		t.Fatal("expected an error for an empty bundle")
	}
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("expected an error for a nil bundle")
	}
}

func TestSlotsFiltering(t *testing.T) {
	p := newTestPool(t, Options{})

	if got := len(p.Slots(SlotFilter{})); got != 5 {
		t.Errorf("unfiltered Slots() = %d, want 5", got)
	}
	if got := len(p.Slots(SlotFilter{Country: "jp"})); got != 2 {
		t.Errorf("Slots(country=jp) = %d, want 2", got)
	}
	if got := len(p.Slots(SlotFilter{City: "us-lax"})); got != 2 {
		t.Errorf("Slots(city=us-lax) = %d, want 2", got)
	}
	if got := len(p.Slots(SlotFilter{OpenOnly: true})); got != 0 {
		t.Errorf("Slots(open) = %d, want 0 before anything is opened", got)
	}
	if got := len(p.Slots(SlotFilter{WithIP: true})); got != 0 {
		t.Errorf("Slots(with_ip) = %d, want 0 before any measurement", got)
	}
	if p.Len() != 5 {
		t.Errorf("Len() = %d, want 5", p.Len())
	}
}

func TestPolicyGeographyMatchingIsCaseInsensitive(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	state.spec.Country = "JP"
	state.spec.City = "JP-TYO"

	p.mu.Lock()
	eligible := p.eligibleLocked(state, policy.Policy{
		Countries: []string{"jp"},
		Cities:    []string{"jp-tyo"},
	}, "", time.Now())
	p.mu.Unlock()
	if !eligible {
		t.Error("lowercase policy did not match uppercase catalog metadata")
	}
}

func TestStatsCountsGeography(t *testing.T) {
	p := newTestPool(t, Options{MaxActive: 3})
	stats := p.Stats()
	if stats.Slots != 5 {
		t.Errorf("Slots = %d, want 5", stats.Slots)
	}
	if stats.Countries != 3 {
		t.Errorf("Countries = %d, want 3", stats.Countries)
	}
	if stats.Cities != 4 {
		t.Errorf("Cities = %d, want 4", stats.Cities)
	}
	if stats.MaxActive != 3 {
		t.Errorf("MaxActive = %d, want 3", stats.MaxActive)
	}
}

func TestCountryAcquisitionsCountSelectedExitCountry(t *testing.T) {
	p := newTestPool(t, Options{})

	p.mu.Lock()
	p.recordAcquisitionLocked(p.slots["jp-tyo-wg-001"])
	p.recordAcquisitionLocked(p.slots["jp-osa-wg-001"])
	p.recordAcquisitionLocked(p.slots["us-lax-wg-001"])
	p.mu.Unlock()

	got := p.CountryAcquisitions()
	if len(got) != 2 {
		t.Fatalf("CountryAcquisitions() = %+v, want two countries", got)
	}
	if got[0].Country != "jp" || got[0].Acquisitions != 2 {
		t.Errorf("first country = %+v, want jp=2", got[0])
	}
	if got[1].Country != "us" || got[1].Acquisitions != 1 {
		t.Errorf("second country = %+v, want us=1", got[1])
	}
	if p.Stats().Acquisitions != 3 {
		t.Errorf("total acquisitions = %d, want 3", p.Stats().Acquisitions)
	}
}

func TestAcquireRejectsImpossiblePolicy(t *testing.T) {
	p := newTestPool(t, Options{})
	ctx := context.Background()

	// No slot has this country, so selection fails before any dial is attempted.
	if _, err := p.Acquire(ctx, policy.Policy{Countries: []string{"zz"}}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Acquire(cc=zz) error = %v, want ErrNoCandidate", err)
	}
	if _, err := p.Acquire(ctx, policy.Policy{Slot: "nope"}, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Acquire(slot=nope) error = %v, want ErrNoCandidate", err)
	}
	if _, err := p.Acquire(ctx, policy.Policy{Cities: []string{"xx-yyy"}}, ""); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("Acquire(city=xx-yyy) error = %v, want ErrNoCandidate", err)
	}
}

func TestExcludedIPRemovesCandidate(t *testing.T) {
	p := newTestPool(t, Options{})
	ip := netip.MustParseAddr("203.0.113.9")

	p.mu.Lock()
	p.slots["jp-tyo-wg-001"].publicIP = ip
	p.slots["jp-tyo-wg-001"].ipCheckedAt = time.Now()
	p.mu.Unlock()

	pol := policy.Policy{Slot: "jp-tyo-wg-001", ExcludeIPs: []netip.Addr{ip}}
	if _, err := p.Acquire(context.Background(), pol, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("error = %v, want ErrNoCandidate when the only slot's IP is excluded", err)
	}
}

func TestReportPutsSlotOnCooldownPerTarget(t *testing.T) {
	p := newTestPool(t, Options{Cooldown: time.Hour})

	result, err := p.Report(ReportInput{Slot: "us-lax-wg-001", Target: "example.com", Reason: "http_403"})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if result.Slot != "us-lax-wg-001" || result.Cooldown != time.Hour {
		t.Fatalf("unexpected result %+v", result)
	}

	// The slot is unavailable for that destination...
	pol := policy.Policy{Slot: "us-lax-wg-001"}
	if _, err := p.Acquire(context.Background(), pol, "example.com"); !errors.Is(err, ErrNoCandidate) {
		t.Errorf("slot was still offered for the reported target: %v", err)
	}
	// ...but remains a candidate everywhere else, which is why cooldowns are
	// scoped per target rather than global.
	p.mu.Lock()
	stillEligible := p.eligibleLocked(p.slots["us-lax-wg-001"], pol, "other.example", time.Now())
	p.mu.Unlock()
	if !stillEligible {
		t.Error("a per-target cooldown must not disable the slot for other targets")
	}
}

func TestReportWithoutTargetDisablesSlot(t *testing.T) {
	p := newTestPool(t, Options{Cooldown: time.Minute})
	if _, err := p.Report(ReportInput{Slot: "de-fra-wg-001"}); err != nil {
		t.Fatalf("Report: %v", err)
	}
	p.mu.Lock()
	disabled := time.Now().Before(p.slots["de-fra-wg-001"].disabledUntil)
	p.mu.Unlock()
	if !disabled {
		t.Error("a report without a target should back the slot off entirely")
	}
}

func TestReportUnknownTargets(t *testing.T) {
	p := newTestPool(t, Options{})
	if _, err := p.Report(ReportInput{Slot: "does-not-exist"}); err == nil {
		t.Error("expected an error for an unknown slot")
	}
	if _, err := p.Report(ReportInput{Session: "never-bound"}); err == nil {
		t.Error("expected an error for an unknown session")
	}
}

func TestRotateAndSessionLookup(t *testing.T) {
	p := newTestPool(t, Options{SessionTTL: time.Minute})

	if p.Rotate("unknown") {
		t.Error("Rotate on an unbound session should report false")
	}
	if _, ok := p.Session("unknown"); ok {
		t.Error("Session on an unbound name should report false")
	}

	// Simulate a binding the way Acquire would.
	p.mu.Lock()
	p.bindSession(policy.Policy{Session: "job-1"}, "jp-tyo-wg-001")
	p.mu.Unlock()

	info, ok := p.Session("job-1")
	if !ok {
		t.Fatal("Session(job-1) not found after binding")
	}
	if info.Slot != "jp-tyo-wg-001" || info.Country != "jp" {
		t.Errorf("unexpected session info %+v", info)
	}
	if !p.Rotate("job-1") {
		t.Error("Rotate should report true for a bound session")
	}
	if _, ok := p.Session("job-1"); ok {
		t.Error("session survived rotation")
	}
	if p.Stats().Rotations != 1 {
		t.Errorf("Rotations = %d, want 1", p.Stats().Rotations)
	}
}

func TestExpiredSessionIsNotReturned(t *testing.T) {
	p := newTestPool(t, Options{})
	p.mu.Lock()
	p.sessions["stale"] = &session{slotID: "jp-tyo-wg-001", expiresAt: time.Now().Add(-time.Second)}
	p.mu.Unlock()

	if _, ok := p.Session("stale"); ok {
		t.Error("an expired session must not be reported as bound")
	}
}

func TestUniqueBatchExcludesUsedSlotsAndIPs(t *testing.T) {
	p := newTestPool(t, Options{BatchTTL: time.Hour})
	ip := netip.MustParseAddr("198.51.100.50")

	p.mu.Lock()
	state := p.slots["us-lax-wg-001"]
	state.publicIP = ip
	// Record the slot as already served within this batch.
	p.recordBatch(policy.Policy{UniqueBatch: "b1"}, state, ip)
	// A different slot that happens to share the same public IP.
	other := p.slots["us-lax-wg-002"]
	other.publicIP = ip
	now := time.Now()
	usedSlot := p.eligibleLocked(state, policy.Policy{UniqueBatch: "b1"}, "", now)
	sharedIP := p.eligibleLocked(other, policy.Policy{UniqueBatch: "b1"}, "", now)
	freeSlot := p.eligibleLocked(p.slots["de-fra-wg-001"], policy.Policy{UniqueBatch: "b1"}, "", now)
	p.mu.Unlock()

	if usedSlot {
		t.Error("a slot already used in the batch must not be reused")
	}
	if sharedIP {
		t.Error("a different slot sharing an already-used public IP must not be reused")
	}
	if !freeSlot {
		t.Error("an unused slot must remain eligible")
	}
}

func TestInventoryRoundTrip(t *testing.T) {
	p := newTestPool(t, Options{})
	path := filepath.Join(t.TempDir(), "state", "inventory.json")

	checked := time.Now().Truncate(time.Second)
	p.mu.Lock()
	p.slots["jp-tyo-wg-001"].publicIP = netip.MustParseAddr("203.0.113.1")
	p.slots["jp-tyo-wg-001"].ipCheckedAt = checked
	p.slots["us-lax-wg-001"].publicIP = netip.MustParseAddr("203.0.113.2")
	p.slots["us-lax-wg-001"].ipCheckedAt = checked
	p.mu.Unlock()

	if err := p.SaveInventory(path); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}
	if got := p.UniquePublicIPs(); len(got) != 2 {
		t.Errorf("UniquePublicIPs() = %v, want 2 entries", got)
	}

	restored := newTestPool(t, Options{})
	count, err := restored.LoadInventory(path)
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if count != 2 {
		t.Fatalf("LoadInventory restored %d slots, want 2", count)
	}
	if got := restored.Stats().UniqueIPs; got != 2 {
		t.Errorf("UniqueIPs after restore = %d, want 2", got)
	}
}

func TestLoadInventoryMissingFileIsNotAnError(t *testing.T) {
	p := newTestPool(t, Options{})
	count, err := p.LoadInventory(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatalf("LoadInventory: %v", err)
	}
	if count != 0 {
		t.Errorf("count = %d, want 0", count)
	}
}

func TestSaveInventoryWithNothingMeasured(t *testing.T) {
	p := newTestPool(t, Options{})
	// Nothing has been measured yet, so there is nothing worth persisting and
	// no file should be required.
	if err := p.SaveInventory(filepath.Join(t.TempDir(), "inv.json")); err != nil {
		t.Fatalf("SaveInventory: %v", err)
	}
}

func TestExpireLockedDropsStaleEntries(t *testing.T) {
	p := newTestPool(t, Options{})
	past := time.Now().Add(-time.Hour)

	p.mu.Lock()
	p.sessions["old"] = &session{slotID: "jp-tyo-wg-001", expiresAt: past}
	p.batches["old"] = &batch{usedIPs: map[netip.Addr]struct{}{}, usedSlots: map[string]struct{}{}, expiresAt: past}
	p.slots["jp-tyo-wg-001"].cooldowns["example.com"] = past
	p.expireLocked(time.Now())
	sessions, batches, cooldowns := len(p.sessions), len(p.batches), len(p.slots["jp-tyo-wg-001"].cooldowns)
	p.mu.Unlock()

	if sessions != 0 || batches != 0 || cooldowns != 0 {
		t.Errorf("stale entries survived: sessions=%d batches=%d cooldowns=%d", sessions, batches, cooldowns)
	}
}

func TestWarmupWithZeroCount(t *testing.T) {
	p := newTestPool(t, Options{})
	if got := p.Warmup(context.Background(), 0); got != 0 {
		t.Errorf("Warmup(0) = %d, want 0", got)
	}
}
