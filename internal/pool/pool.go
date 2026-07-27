// Package pool owns every egress slot: their tunnels, their health, their
// measured public IP, and the policy that decides which one serves a request.
//
// The pool is the reason this project exists. Bringing up a userspace WireGuard
// tunnel is a solved problem; deciding *which* of several hundred tunnels a
// given connection should use — while honouring sticky sessions, unique-IP
// batches and per-target cooldowns — is the part that has to be built.
package pool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/minpeter-labs/global-egress/internal/catalog"
	"github.com/minpeter-labs/global-egress/internal/policy"
	"github.com/minpeter-labs/global-egress/internal/wgtunnel"
)

// Errors returned by Acquire.
var (
	// ErrNoCandidate means the policy matched no usable slot.
	ErrNoCandidate = errors.New("pool: no slot satisfies the requested policy")
	// ErrExhausted means every candidate failed to come up.
	ErrExhausted = errors.New("pool: all candidate slots failed")
	// ErrCapacity means the active-tunnel budget is fully used by live requests.
	ErrCapacity = errors.New("pool: tunnel capacity exhausted")
	// ErrTunnelBudget means the new-tunnel rate budget is spent. Serving from an
	// already-open tunnel is still possible; only opening another one is not.
	ErrTunnelBudget = errors.New("pool: new-tunnel rate budget exhausted")
)

// Options configures a Pool.
type Options struct {
	// MaxActive caps how many tunnels may be up at once. Zero means "all slots".
	MaxActive int
	// SessionTTL is the default lifetime of a sticky session.
	SessionTTL time.Duration
	// BatchTTL is how long a unique-IP batch remembers the IPs it used.
	BatchTTL time.Duration
	// Cooldown is the default per-target cooldown applied by Report.
	Cooldown time.Duration
	// IdleTimeout closes tunnels that have served nothing for this long.
	// Zero disables idle eviction.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds how long Acquire waits for a new tunnel.
	HandshakeTimeout time.Duration
	// DialAttempts is how many candidate slots Acquire tries before failing.
	DialAttempts int
	// FailureBackoff is the base backoff applied to a slot after a failure.
	FailureBackoff time.Duration
	// NewTunnelBudget caps how many tunnels may be *opened* per
	// NewTunnelWindow. Zero disables the limit.
	//
	// This exists because providers restrict how quickly one device key may
	// associate with new relays. Exceeding that looks like key sharing and can
	// get the key blocked for hours, which is far worse than a slow rotation.
	// The cap counts attempts, since a failed handshake still contacts a relay.
	NewTunnelBudget int
	// NewTunnelWindow is the period NewTunnelBudget applies to.
	NewTunnelWindow time.Duration
	// EntryExploreRate is the probability of trying the second-best entry instead
	// of the best one, so alternatives keep being measured. Zero selects the
	// default; use DisableEntryExploration to turn it off.
	EntryExploreRate float64
	// DisableEntryExploration pins selection to the best known entry. Useful for
	// reproducible tests and for operators who prefer stable routing over
	// self-correcting routing.
	DisableEntryExploration bool
	// IPCheckURL returns the caller's public address. Empty disables IP checks,
	// which also disables unique-IP guarantees.
	IPCheckURL string
	// IPCheckTimeout bounds a single public-IP measurement.
	IPCheckTimeout time.Duration
	// IPRefreshInterval is how long a measured public IP stays trusted.
	IPRefreshInterval time.Duration
	// IPCheckConcurrency caps simultaneous public-IP measurements. This is a
	// courtesy limit: the check hits a third-party service.
	IPCheckConcurrency int
	// Logger receives pool events.
	Logger *slog.Logger
	// Rand, when non-nil, makes selection deterministic for tests.
	Rand *rand.Rand
}

func (o *Options) applyDefaults() {
	if o.SessionTTL <= 0 {
		o.SessionTTL = 10 * time.Minute
	}
	if o.BatchTTL <= 0 {
		o.BatchTTL = 15 * time.Minute
	}
	if o.Cooldown <= 0 {
		o.Cooldown = 15 * time.Minute
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = 12 * time.Second
	}
	if o.DialAttempts <= 0 {
		o.DialAttempts = 3
	}
	if o.FailureBackoff <= 0 {
		o.FailureBackoff = 30 * time.Second
	}
	if o.NewTunnelWindow <= 0 {
		o.NewTunnelWindow = 10 * time.Minute
	}
	// A negative rate cannot be expressed as "off" here, because zero has to mean
	// "use the default"; DisableEntryExploration is the explicit switch.
	if o.EntryExploreRate <= 0 {
		o.EntryExploreRate = 0.1
	}
	if o.DisableEntryExploration {
		o.EntryExploreRate = 0
	}
	if o.IPCheckTimeout <= 0 {
		o.IPCheckTimeout = 15 * time.Second
	}
	if o.IPRefreshInterval <= 0 {
		o.IPRefreshInterval = 6 * time.Hour
	}
	if o.IPCheckConcurrency <= 0 {
		o.IPCheckConcurrency = 4
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// slotState is the mutable bookkeeping for one slot.
type slotState struct {
	spec Spec

	tunnel  *wgtunnel.Tunnel
	opening chan struct{} // non-nil while an Open is in flight

	openedAt time.Time
	lastUsed time.Time
	leases   int

	publicIP    netip.Addr
	ipCheckedAt time.Time
	ipChecking  bool

	failures      int
	lastError     string
	disabledUntil time.Time

	// cooldowns maps a destination host to the time the slot may serve it again.
	cooldowns map[string]time.Time
}

func (s *slotState) isOpen() bool { return s.tunnel != nil }

// ready reports whether the slot can serve a request without opening a tunnel.
// Relay-socks slots ride on the shared entries, so they never need one; a
// WireGuard slot only qualifies while its own tunnel is up.
func (s *slotState) ready() bool {
	return s.spec.Kind == KindRelaySocks || s.isOpen()
}

func (s *slotState) coolingDown(target string, now time.Time) bool {
	if target == "" || len(s.cooldowns) == 0 {
		return false
	}
	until, ok := s.cooldowns[target]
	return ok && now.Before(until)
}

type session struct {
	slotID    string
	expiresAt time.Time
}

type batch struct {
	usedIPs   map[netip.Addr]struct{}
	usedSlots map[string]struct{}
	expiresAt time.Time
}

// Pool manages the whole slot inventory.
type Pool struct {
	opts Options
	log  *slog.Logger

	ipCheckSem chan struct{}

	mu       sync.Mutex
	rng      *rand.Rand
	slots    map[string]*slotState
	order    []string // slot IDs in stable (sorted) order
	sessions map[string]*session
	batches  map[string]*batch
	// entries are the WireGuard tunnels that relay-socks slots ride on. Empty in
	// pure WireGuard mode.
	entries []*entryState
	// opens holds the timestamps of recent tunnel openings, newest last, pruned
	// to NewTunnelWindow.
	opens []time.Time
	// closing is set by Close so background work stops starting.
	closing bool

	// baseCtx is cancelled by Close. Background work such as public-IP checks
	// derives from it, so a shutdown does not leave requests in flight against
	// tunnels that are being torn down. Holding a context in a struct is a
	// deliberate exception, justified the same way http.Server justifies
	// BaseContext: the object has an explicit lifetime ended by Close.
	baseCtx   context.Context
	cancelAll context.CancelFunc
	// wg tracks every goroutine the pool owns, so Close can wait for them.
	wg sync.WaitGroup

	// counters, protected by mu
	statAcquired uint64
	statRotated  uint64
	statReports  uint64
	statFailures uint64
}

// New builds a pool where every slot owns a WireGuard tunnel.
func New(bundle *catalog.Bundle, opts Options) (*Pool, error) {
	if bundle == nil || len(bundle.Slots) == 0 {
		return nil, errors.New("pool: bundle contains no slots")
	}
	return NewWithSpecs(SpecsFromBundle(bundle), nil, opts)
}

// NewWithSpecs builds a pool from explicit slot specifications.
//
// entries are the WireGuard tunnels that relay-socks slots are reached through.
// They are required if any spec is KindRelaySocks and ignored otherwise.
func NewWithSpecs(specs []Spec, entries []catalog.Slot, opts Options) (*Pool, error) {
	if len(specs) == 0 {
		return nil, errors.New("pool: no slots")
	}
	needsEntry := false
	for _, spec := range specs {
		if spec.Kind == KindRelaySocks {
			needsEntry = true
			break
		}
	}
	if needsEntry && len(entries) == 0 {
		return nil, errors.New("pool: relay-socks slots require at least one entry tunnel")
	}
	opts.applyDefaults()

	rng := opts.Rand
	if rng == nil {
		// math/rand/v2 seeds itself from the runtime, so there is nothing to seed
		// here; a fresh generator only exists so tests can substitute their own.
		rng = rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	}

	baseCtx, cancelAll := context.WithCancel(context.Background())
	p := &Pool{
		baseCtx:    baseCtx,
		cancelAll:  cancelAll,
		opts:       opts,
		log:        opts.Logger,
		ipCheckSem: make(chan struct{}, opts.IPCheckConcurrency),
		rng:        rng,
		slots:      make(map[string]*slotState, len(specs)),
		sessions:   make(map[string]*session),
		batches:    make(map[string]*batch),
	}
	for _, spec := range specs {
		if _, dup := p.slots[spec.ID]; dup {
			return nil, fmt.Errorf("pool: duplicate slot id %q", spec.ID)
		}
		p.slots[spec.ID] = &slotState{spec: spec, cooldowns: make(map[string]time.Time)}
		p.order = append(p.order, spec.ID)
	}
	sort.Strings(p.order)

	for _, entry := range entries {
		p.entries = append(p.entries, &entryState{
			spec:    entry,
			latency: make(map[string]time.Duration),
			samples: make(map[string]int),
		})
	}
	return p, nil
}

// Len returns the number of known slots.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.slots)
}

// Lease is a slot borrowed for one connection. Release must always be called.
type Lease struct {
	pool   *Pool
	state  *slotState
	dialer Dialer

	// Slot describes the chosen egress.
	Slot Spec
	// Entry is the entry tunnel used, for relay-socks slots.
	Entry string
	// Chained reports that traffic leaves through a proxy rather than directly
	// out of a tunnel. The connection's remote address is then the proxy, not the
	// destination, so callers must not treat it as the resolved destination.
	Chained bool
	// PublicIP is the last measured public address, invalid when unknown.
	PublicIP netip.Addr
	// Session is the sticky session the lease belongs to, if any.
	Session string

	released bool
}

// DialContext connects to address through the leased egress.
func (l *Lease) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return l.dialer.DialContext(ctx, network, address)
}

// Release returns the slot to the pool.
func (l *Lease) Release() {
	if l == nil || l.released {
		return
	}
	l.released = true
	l.pool.mu.Lock()
	if l.state.leases > 0 {
		l.state.leases--
	}
	l.state.lastUsed = time.Now()
	l.pool.mu.Unlock()
}

// Acquire selects a slot for a connection to target (a host name or IP, used for
// per-target cooldown bookkeeping; it may be empty).
func (p *Pool) Acquire(ctx context.Context, pol policy.Policy, target string) (*Lease, error) {
	attempts := p.opts.DialAttempts
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		state, sticky, err := p.pick(pol, target)
		if err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}

		dialer, entryID, err := p.ensureDialer(ctx, state)
		if err != nil {
			p.noteFailure(state, err)
			lastErr = err
			// A sticky session pointing at a broken slot must not pin the client
			// to it; drop the binding so the next attempt is free to move on.
			if sticky && pol.Session != "" {
				p.dropSession(pol.Session)
			}
			continue
		}

		p.mu.Lock()
		state.leases++
		state.lastUsed = time.Now()
		state.failures = 0
		state.lastError = ""
		publicIP := state.publicIP
		p.bindSession(pol, state.ID())
		p.recordBatch(pol, state, publicIP)
		p.statAcquired++
		p.mu.Unlock()

		p.maybeCheckIP(state)

		return &Lease{
			pool:     p,
			state:    state,
			dialer:   dialer,
			Slot:     state.spec,
			Entry:    entryID,
			Chained:  state.spec.Kind == KindRelaySocks,
			PublicIP: publicIP,
			Session:  pol.Session,
		}, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrExhausted, lastErr)
	}
	return nil, ErrExhausted
}

// ID returns the slot ID.
func (s *slotState) ID() string { return s.spec.ID }

// pick chooses the next slot to try. The returned bool reports whether the
// choice came from a sticky session.
func (p *Pool) pick(pol policy.Policy, target string) (*slotState, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	p.expireLocked(now)

	// A live sticky session wins, as long as the slot is still usable.
	if pol.Session != "" {
		if sess, ok := p.sessions[pol.Session]; ok && now.Before(sess.expiresAt) {
			if state, ok := p.slots[sess.slotID]; ok && p.eligibleLocked(state, pol, target, now) {
				sess.expiresAt = now.Add(p.sessionTTL(pol))
				return state, true, nil
			}
			// The pinned slot became unusable: fall through and re-pick.
			delete(p.sessions, pol.Session)
		}
	}

	candidates := make([]*slotState, 0, 32)
	for _, id := range p.order {
		state := p.slots[id]
		if p.eligibleLocked(state, pol, target, now) {
			candidates = append(candidates, state)
		}
	}
	if len(candidates) == 0 {
		return nil, false, ErrNoCandidate
	}

	// Prefer slots that need no handshake: relay-socks slots always, and
	// WireGuard slots whose tunnel is already up. With a healthy active set there
	// is still plenty of IP diversity among them.
	ready := candidates[:0:0]
	for _, state := range candidates {
		if state.ready() {
			ready = append(ready, state)
		}
	}
	if len(ready) > 0 {
		return ready[p.rng.IntN(len(ready))], false, nil
	}

	// Only WireGuard slots that need a new tunnel are left, so the tunnel budgets
	// apply. They must not gate relay-socks slots, which open nothing: doing so
	// would fail requests the pool could serve.
	if !p.tunnelBudgetAvailableLocked(now) {
		return nil, false, ErrTunnelBudget
	}
	if err := p.reserveCapacityLocked(); err != nil {
		return nil, false, err
	}
	return candidates[p.rng.IntN(len(candidates))], false, nil
}

// eligibleLocked applies every filter that can be evaluated without I/O.
func (p *Pool) eligibleLocked(state *slotState, pol policy.Policy, target string, now time.Time) bool {
	if state == nil {
		return false
	}
	if now.Before(state.disabledUntil) {
		return false
	}
	if pol.Slot != "" && state.spec.ID != pol.Slot {
		return false
	}
	if len(pol.Countries) > 0 && !containsFold(pol.Countries, state.spec.Country) {
		return false
	}
	if len(pol.Cities) > 0 && !containsFold(pol.Cities, state.spec.City) {
		return false
	}
	if state.coolingDown(target, now) {
		return false
	}
	if len(pol.ExcludeIPs) > 0 && state.publicIP.IsValid() {
		for _, excluded := range pol.ExcludeIPs {
			if excluded == state.publicIP {
				return false
			}
		}
	}
	if pol.UniqueBatch != "" {
		if b, ok := p.batches[pol.UniqueBatch]; ok && now.Before(b.expiresAt) {
			if _, used := b.usedSlots[state.spec.ID]; used {
				return false
			}
			if state.publicIP.IsValid() {
				if _, used := b.usedIPs[state.publicIP]; used {
					return false
				}
			}
		}
	}
	return true
}

// reserveCapacityLocked checks whether another tunnel may be opened, closing an
// idle one if the budget is full.
func (p *Pool) reserveCapacityLocked() error {
	if p.opts.MaxActive <= 0 {
		return nil
	}
	openCount := 0
	for _, state := range p.slots {
		if state.isOpen() || state.opening != nil {
			openCount++
		}
	}
	if openCount < p.opts.MaxActive {
		return nil
	}

	// Evict the least recently used idle tunnel.
	var victim *slotState
	for _, state := range p.slots {
		if !state.isOpen() || state.leases > 0 {
			continue
		}
		if victim == nil || state.lastUsed.Before(victim.lastUsed) {
			victim = state
		}
	}
	if victim == nil {
		return ErrCapacity
	}
	p.closeLocked(victim, "evicted to free capacity")
	return nil
}

// closeLocked tears down a tunnel. Caller must hold mu.
func (p *Pool) closeLocked(state *slotState, reason string) {
	if state.tunnel == nil {
		return
	}
	tunnel := state.tunnel
	state.tunnel = nil
	state.openedAt = time.Time{}
	id := state.spec.ID
	p.log.Debug("closing tunnel", slog.String("slot", id), slog.String("reason", reason))
	// Tear down off the lock, because a device close joins its own goroutines.
	// Registered with the WaitGroup so Close can wait for it.
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := tunnel.Close(); err != nil {
			p.log.Warn("tunnel close failed", slog.String("slot", id), slog.Any("error", err))
		}
	}()
}

// ensureDialer returns something that can reach the internet as this slot, plus
// the entry tunnel used (empty for WireGuard slots).
func (p *Pool) ensureDialer(ctx context.Context, state *slotState) (Dialer, string, error) {
	if state.spec.Kind == KindRelaySocks {
		return p.dialerForSocksSlot(ctx, state)
	}
	tunnel, err := p.ensureOpen(ctx, state)
	if err != nil {
		return nil, "", err
	}
	return tunnel, "", nil
}

// ensureOpen returns a live tunnel for the slot, opening one if needed. Only one
// caller opens a given slot; the others wait for it.
func (p *Pool) ensureOpen(ctx context.Context, state *slotState) (*wgtunnel.Tunnel, error) {
	for {
		p.mu.Lock()
		if state.tunnel != nil {
			tunnel := state.tunnel
			p.mu.Unlock()
			return tunnel, nil
		}
		if waiting := state.opening; waiting != nil {
			p.mu.Unlock()
			select {
			case <-waiting:
				continue // re-check: the opener either succeeded or failed
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		done := make(chan struct{})
		state.opening = done
		spec := state.spec.WG
		p.mu.Unlock()

		tunnel, err := p.openTunnel(ctx, spec)

		p.mu.Lock()
		state.opening = nil
		if err == nil {
			state.tunnel = tunnel
			state.openedAt = time.Now()
		}
		p.mu.Unlock()
		close(done)

		if err != nil {
			return nil, err
		}
		return tunnel, nil
	}
}

// tunnelBudgetAvailableLocked reports whether another tunnel may be opened now.
func (p *Pool) tunnelBudgetAvailableLocked(now time.Time) bool {
	if p.opts.NewTunnelBudget <= 0 {
		return true
	}
	p.pruneOpensLocked(now)
	return len(p.opens) < p.opts.NewTunnelBudget
}

func (p *Pool) pruneOpensLocked(now time.Time) {
	cutoff := now.Add(-p.opts.NewTunnelWindow)
	keep := 0
	for _, at := range p.opens {
		if at.After(cutoff) {
			break
		}
		keep++
	}
	if keep > 0 {
		p.opens = append(p.opens[:0], p.opens[keep:]...)
	}
}

// noteTunnelOpen records one relay contact against the rate budget.
func (p *Pool) noteTunnelOpen(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneOpensLocked(now)
	p.opens = append(p.opens, now)
}

func (p *Pool) openTunnel(ctx context.Context, spec catalog.Slot) (*wgtunnel.Tunnel, error) {
	// Count the attempt before making it: a failed handshake still contacts the
	// relay, and that is what the provider's limit reacts to.
	p.noteTunnelOpen(time.Now())

	openCtx, cancel := context.WithTimeout(ctx, p.opts.HandshakeTimeout)
	defer cancel()

	started := time.Now()
	tunnel, err := wgtunnel.Open(openCtx, spec, p.log)
	if err != nil {
		return nil, err
	}
	if err := tunnel.WaitHandshake(openCtx); err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	p.log.Info("tunnel up",
		slog.String("slot", spec.ID),
		slog.String("endpoint", spec.Endpoint),
		slog.Duration("took", time.Since(started)))
	return tunnel, nil
}

func (p *Pool) noteFailure(state *slotState, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	state.failures++
	state.lastError = err.Error()
	p.statFailures++
	// Exponential backoff, capped, so a dead server stops being retried without
	// being removed from the catalog.
	backoff := p.opts.FailureBackoff << min(state.failures-1, 5)
	if maxBackoff := 30 * time.Minute; backoff > maxBackoff {
		backoff = maxBackoff
	}
	state.disabledUntil = time.Now().Add(backoff)
	if state.tunnel != nil {
		p.closeLocked(state, "failure")
	}
	p.log.Warn("slot failed",
		slog.String("slot", state.spec.ID),
		slog.Int("failures", state.failures),
		slog.Duration("backoff", backoff),
		slog.Any("error", err))
}

func (p *Pool) sessionTTL(pol policy.Policy) time.Duration {
	if pol.TTL > 0 {
		return pol.TTL
	}
	return p.opts.SessionTTL
}

// bindSession records the sticky mapping. Caller must hold mu.
func (p *Pool) bindSession(pol policy.Policy, slotID string) {
	if pol.Session == "" {
		return
	}
	p.sessions[pol.Session] = &session{slotID: slotID, expiresAt: time.Now().Add(p.sessionTTL(pol))}
}

// recordBatch remembers what a unique-IP batch has consumed. Caller holds mu.
func (p *Pool) recordBatch(pol policy.Policy, state *slotState, ip netip.Addr) {
	if pol.UniqueBatch == "" {
		return
	}
	b, ok := p.batches[pol.UniqueBatch]
	if !ok || time.Now().After(b.expiresAt) {
		b = &batch{usedIPs: make(map[netip.Addr]struct{}), usedSlots: make(map[string]struct{})}
		p.batches[pol.UniqueBatch] = b
	}
	b.expiresAt = time.Now().Add(p.opts.BatchTTL)
	b.usedSlots[state.spec.ID] = struct{}{}
	if ip.IsValid() {
		b.usedIPs[ip] = struct{}{}
	}
}

func (p *Pool) dropSession(name string) {
	p.mu.Lock()
	delete(p.sessions, name)
	p.mu.Unlock()
}

// NoteDialFailure records that a leased slot could not reach its destination.
// The slot backs off, so the next attempt picks a different one. Relays disappear
// from DNS and proxies refuse connections often enough that this has to be a
// normal, cheap event rather than an error surfaced to the client.
func (p *Pool) NoteDialFailure(lease *Lease, err error) {
	if lease == nil || lease.state == nil || err == nil {
		return
	}
	p.noteFailure(lease.state, err)
}

// Rotate forgets a sticky session so the next request picks a new slot. It
// reports whether the session existed.
func (p *Pool) Rotate(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, existed := p.sessions[name]
	delete(p.sessions, name)
	if existed {
		p.statRotated++
	}
	return existed
}

// ReportInput describes a client-observed problem with an egress.
type ReportInput struct {
	// Session identifies the sticky session to rotate. Optional.
	Session string
	// Slot names the slot directly. Optional when Session is set.
	Slot string
	// Target is the destination host the block was observed on. When empty the
	// cooldown applies to every destination.
	Target string
	// Reason is free-form, for logs only.
	Reason string
	// Cooldown overrides the configured default.
	Cooldown time.Duration
}

// ReportResult describes what a report changed.
type ReportResult struct {
	Slot     string        `json:"slot"`
	Target   string        `json:"target,omitempty"`
	Until    time.Time     `json:"cooldown_until"`
	Cooldown time.Duration `json:"cooldown"`
	Rotated  bool          `json:"session_rotated"`
}

// Report puts a slot on cooldown for a destination and rotates the reporting
// session. Blocks are usually per-site, so the slot stays available for every
// other destination.
func (p *Pool) Report(in ReportInput) (ReportResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	slotID := in.Slot
	if slotID == "" && in.Session != "" {
		sess, ok := p.sessions[in.Session]
		if !ok {
			return ReportResult{}, fmt.Errorf("pool: unknown session %q", in.Session)
		}
		slotID = sess.slotID
	}
	state, ok := p.slots[slotID]
	if !ok {
		return ReportResult{}, fmt.Errorf("pool: unknown slot %q", slotID)
	}

	cooldown := in.Cooldown
	if cooldown <= 0 {
		cooldown = p.opts.Cooldown
	}
	until := time.Now().Add(cooldown)

	if in.Target == "" {
		// A global complaint: back the slot off entirely.
		state.disabledUntil = until
	} else {
		state.cooldowns[in.Target] = until
	}

	rotated := false
	if in.Session != "" {
		if _, existed := p.sessions[in.Session]; existed {
			delete(p.sessions, in.Session)
			rotated = true
			p.statRotated++
		}
	}
	p.statReports++

	p.log.Info("egress reported",
		slog.String("slot", slotID),
		slog.String("target", in.Target),
		slog.String("reason", in.Reason),
		slog.Duration("cooldown", cooldown))

	return ReportResult{
		Slot:     slotID,
		Target:   in.Target,
		Until:    until,
		Cooldown: cooldown,
		Rotated:  rotated,
	}, nil
}

// SessionInfo describes a sticky session.
type SessionInfo struct {
	Session   string     `json:"session"`
	Slot      string     `json:"slot"`
	Country   string     `json:"country,omitempty"`
	City      string     `json:"city,omitempty"`
	PublicIP  string     `json:"public_ip,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	CheckedAt *time.Time `json:"ip_checked_at,omitempty"`
}

// Session returns the current binding for a sticky session name.
func (p *Pool) Session(name string) (SessionInfo, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	sess, ok := p.sessions[name]
	if !ok || time.Now().After(sess.expiresAt) {
		return SessionInfo{}, false
	}
	state, ok := p.slots[sess.slotID]
	if !ok {
		return SessionInfo{}, false
	}
	info := SessionInfo{
		Session:   name,
		Slot:      state.spec.ID,
		Country:   state.spec.Country,
		City:      state.spec.City,
		ExpiresAt: sess.expiresAt,
	}
	if state.publicIP.IsValid() {
		info.PublicIP = state.publicIP.String()
	}
	if !state.ipCheckedAt.IsZero() {
		at := state.ipCheckedAt
		info.CheckedAt = &at
	}
	return info, true
}

// Warmup opens up to count distinct tunnels so early requests do not pay for a
// handshake. It returns the number of tunnels that came up.
//
// Acquire cannot be used for this: it deliberately prefers tunnels that are
// already open, so calling it in a loop would keep reusing the first one.
func (p *Pool) Warmup(ctx context.Context, count int) int {
	if count <= 0 {
		return 0
	}
	// In relay mode the expensive resource is the entry tunnels, not the slots,
	// so warming means bringing the entries up.
	if len(p.entries) > 0 {
		return p.warmupEntries(ctx)
	}
	if p.opts.MaxActive > 0 && count > p.opts.MaxActive {
		count = p.opts.MaxActive
	}

	p.mu.Lock()
	now := time.Now()
	if p.opts.NewTunnelBudget > 0 {
		p.pruneOpensLocked(now)
		if remaining := p.opts.NewTunnelBudget - len(p.opens); remaining < count {
			count = remaining
		}
	}
	if count <= 0 {
		p.mu.Unlock()
		return 0
	}
	var targets []*slotState
	for _, id := range p.order {
		state := p.slots[id]
		if state.isOpen() || state.opening != nil || now.Before(state.disabledUntil) {
			continue
		}
		targets = append(targets, state)
	}
	// Warm a random spread rather than the alphabetically first slots, so the
	// initial active set is not always the same handful of servers.
	p.rng.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	if len(targets) > count {
		targets = targets[:count]
	}
	p.mu.Unlock()

	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for _, state := range targets {
		wg.Add(1)
		go func(st *slotState) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			if _, err := p.ensureOpen(ctx, st); err != nil {
				p.noteFailure(st, err)
				return
			}
			mu.Lock()
			opened++
			mu.Unlock()
			p.maybeCheckIP(st)
		}(state)
	}
	wg.Wait()
	return opened
}

// warmupEntries opens every entry tunnel that the budget allows.
func (p *Pool) warmupEntries(ctx context.Context) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	opened := 0
	for _, entry := range p.entries {
		wg.Add(1)
		go func(e *entryState) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			if _, err := p.ensureEntryOpen(ctx, e); err != nil {
				return
			}
			mu.Lock()
			opened++
			mu.Unlock()
		}(entry)
	}
	wg.Wait()
	return opened
}

// Close tears down every tunnel and waits for the pool's own goroutines to
// finish. It is safe to call more than once.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return
	}
	p.closing = true
	for _, state := range p.slots {
		p.closeLocked(state, "shutdown")
	}
	p.closeEntriesLocked("shutdown")
	p.mu.Unlock()

	// Cancel in-flight background work, such as public-IP measurements, before
	// waiting: otherwise a check with a long timeout would hold up shutdown.
	p.cancelAll()
	p.wg.Wait()
}

// background runs fn in a goroutine the pool owns, so Close can wait for it. It
// reports false if the pool is already closing, in which case fn does not run.
func (p *Pool) background(fn func()) bool {
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return false
	}
	p.wg.Add(1)
	p.mu.Unlock()

	go func() {
		defer p.wg.Done()
		fn()
	}()
	return true
}

// expireLocked drops stale sessions, batches and cooldowns.
func (p *Pool) expireLocked(now time.Time) {
	for name, sess := range p.sessions {
		if now.After(sess.expiresAt) {
			delete(p.sessions, name)
		}
	}
	for name, b := range p.batches {
		if now.After(b.expiresAt) {
			delete(p.batches, name)
		}
	}
	for _, state := range p.slots {
		for target, until := range state.cooldowns {
			if now.After(until) {
				delete(state.cooldowns, target)
			}
		}
	}
}

func containsFold(list []string, value string) bool {
	if value == "" {
		return false
	}
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
