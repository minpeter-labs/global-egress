package pool

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// SlotInfo is the public view of one slot.
type SlotInfo struct {
	ID      string `json:"id"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Kind    string `json:"kind"`
	// Target is the endpoint for WireGuard slots, or the proxy address for
	// relay-socks slots.
	Target string `json:"target"`

	Open   bool `json:"open"`
	Leases int  `json:"leases"`

	PublicIP    string     `json:"public_ip,omitempty"`
	IPCheckedAt *time.Time `json:"ip_checked_at,omitempty"`

	Failures      int        `json:"failures,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	DisabledUntil *time.Time `json:"disabled_until,omitempty"`
	Cooldowns     int        `json:"cooldowns,omitempty"`
}

// SlotFilter narrows a Slots listing.
type SlotFilter struct {
	Country  string
	City     string
	OpenOnly bool
	WithIP   bool
}

// Slots returns a filtered, sorted snapshot of the inventory.
func (p *Pool) Slots(filter SlotFilter) []SlotInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]SlotInfo, 0, len(p.order))
	for _, id := range p.order {
		state := p.slots[id]
		if filter.Country != "" && !strings.EqualFold(state.spec.Country, filter.Country) {
			continue
		}
		if filter.City != "" && !strings.EqualFold(state.spec.City, filter.City) {
			continue
		}
		if filter.OpenOnly && !state.isOpen() {
			continue
		}
		if filter.WithIP && !state.publicIP.IsValid() {
			continue
		}
		info := SlotInfo{
			ID:        state.spec.ID,
			Country:   state.spec.Country,
			City:      state.spec.City,
			Kind:      state.spec.Kind.String(),
			Target:    state.spec.Target(),
			Open:      state.isOpen(),
			Leases:    state.leases,
			Failures:  state.failures,
			LastError: state.lastError,
			Cooldowns: len(state.cooldowns),
		}
		if state.publicIP.IsValid() {
			info.PublicIP = state.publicIP.String()
		}
		if !state.ipCheckedAt.IsZero() {
			at := state.ipCheckedAt
			info.IPCheckedAt = &at
		}
		if !state.disabledUntil.IsZero() && time.Now().Before(state.disabledUntil) {
			until := state.disabledUntil
			info.DisabledUntil = &until
		}
		out = append(out, info)
	}
	return out
}

// Stats summarises pool state.
type Stats struct {
	Slots     int `json:"slots"`
	Open      int `json:"open_tunnels"`
	Leased    int `json:"active_leases"`
	Disabled  int `json:"disabled_slots"`
	KnownIPs  int `json:"slots_with_known_ip"`
	UniqueIPs int `json:"unique_public_ips"`
	Countries int `json:"countries"`
	Cities    int `json:"cities"`
	Sessions  int `json:"sticky_sessions"`
	Batches   int `json:"unique_batches"`
	MaxActive int `json:"max_active"`
	// Entries counts the shared entry tunnels that relay-socks slots ride on.
	Entries     int `json:"entries"`
	EntriesOpen int `json:"entries_open"`
	// NewTunnelsUsed is how much of the new-tunnel rate budget has been spent in
	// the current window, and NewTunnelBudget is the cap. Watching these tells
	// you whether rotation requests are being slowed down to protect the key.
	NewTunnelsUsed  int    `json:"new_tunnels_used"`
	NewTunnelBudget int    `json:"new_tunnel_budget"`
	NewTunnelWindow string `json:"new_tunnel_window"`
	Acquisitions    uint64 `json:"acquisitions"`
	Rotations       uint64 `json:"rotations"`
	Reports         uint64 `json:"reports"`
	Failures        uint64 `json:"failures"`
}

// Stats returns a snapshot of counters and derived inventory numbers.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	p.pruneOpensLocked(now)
	stats := Stats{
		Slots:           len(p.slots),
		Sessions:        len(p.sessions),
		Batches:         len(p.batches),
		MaxActive:       p.opts.MaxActive,
		Entries:         len(p.entries),
		NewTunnelsUsed:  len(p.opens),
		NewTunnelBudget: p.opts.NewTunnelBudget,
		NewTunnelWindow: p.opts.NewTunnelWindow.String(),
		Acquisitions:    p.statAcquired,
		Rotations:       p.statRotated,
		Reports:         p.statReports,
		Failures:        p.statFailures,
	}
	ips := make(map[netip.Addr]struct{})
	countries := make(map[string]struct{})
	cities := make(map[string]struct{})
	for _, state := range p.slots {
		if state.isOpen() {
			stats.Open++
		}
		stats.Leased += state.leases
		if now.Before(state.disabledUntil) {
			stats.Disabled++
		}
		if state.publicIP.IsValid() {
			stats.KnownIPs++
			ips[state.publicIP] = struct{}{}
		}
		if state.spec.Country != "" {
			countries[state.spec.Country] = struct{}{}
		}
		if state.spec.City != "" {
			cities[state.spec.City] = struct{}{}
		}
	}
	for _, entry := range p.entries {
		if entry.isOpen() {
			stats.EntriesOpen++
		}
	}
	stats.UniqueIPs = len(ips)
	stats.Countries = len(countries)
	stats.Cities = len(cities)
	return stats
}

// maybeCheckIP measures a slot's public IP in the background when the cached
// value is missing or stale.
func (p *Pool) maybeCheckIP(state *slotState) {
	if p.opts.IPCheckURL == "" {
		return
	}
	p.mu.Lock()
	fresh := state.publicIP.IsValid() && time.Since(state.ipCheckedAt) < p.opts.IPRefreshInterval
	// A WireGuard slot can only be measured while its tunnel is up; a relay-socks
	// slot can be measured whenever an entry is available.
	if fresh || state.ipChecking ||
		(state.spec.Kind == KindWireGuard && state.tunnel == nil) {
		p.mu.Unlock()
		return
	}
	state.ipChecking = true
	tunnel := state.tunnel
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			state.ipChecking = false
			p.mu.Unlock()
		}()

		select {
		case p.ipCheckSem <- struct{}{}:
			defer func() { <-p.ipCheckSem }()
		case <-time.After(30 * time.Second):
			return // too much contention; try again on a later acquire
		}

		ctx, cancel := context.WithTimeout(context.Background(), p.opts.IPCheckTimeout)
		defer cancel()

		var dialer Dialer = tunnel
		if state.spec.Kind == KindRelaySocks {
			socks, _, err := p.dialerForSocksSlot(ctx, state)
			if err != nil {
				return
			}
			dialer = socks
		}

		ip, err := FetchPublicIP(ctx, dialer, p.opts.IPCheckURL)
		if err != nil {
			p.log.Debug("public IP check failed",
				slog.String("slot", state.spec.ID), slog.Any("error", err))
			return
		}
		p.mu.Lock()
		changed := state.publicIP != ip
		state.publicIP = ip
		state.ipCheckedAt = time.Now()
		p.mu.Unlock()
		if changed {
			p.log.Info("public IP measured",
				slog.String("slot", state.spec.ID), slog.String("public_ip", ip.String()))
		}
	}()
}

// FetchPublicIP asks an echo service for the address a tunnel exits from.
//
// The response is accepted either as a bare address or as JSON containing an
// "ip" field, which covers both plain echo endpoints and richer services.
func FetchPublicIP(ctx context.Context, dialer Dialer, url string) (netip.Addr, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			ForceAttemptHTTP2:     false,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", "global-egress/ip-check")
	resp, err := client.Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("ip check: unexpected status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return netip.Addr{}, err
	}

	text := strings.TrimSpace(string(body))
	if addr, err := netip.ParseAddr(text); err == nil {
		return addr, nil
	}
	var payload struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(body, &payload); err == nil && payload.IP != "" {
		addr, err := netip.ParseAddr(strings.TrimSpace(payload.IP))
		if err == nil {
			return addr, nil
		}
	}
	preview := text
	if len(preview) > 80 {
		preview = preview[:80] + "..."
	}
	return netip.Addr{}, fmt.Errorf("ip check: cannot parse response %q", preview)
}

// ProbeResult is one measurement produced by Probe.
type ProbeResult struct {
	Slot     string        `json:"slot"`
	Country  string        `json:"country,omitempty"`
	City     string        `json:"city,omitempty"`
	Endpoint string        `json:"endpoint"`
	PublicIP string        `json:"public_ip,omitempty"`
	Latency  time.Duration `json:"latency"`
	Err      string        `json:"error,omitempty"`
}

// ProbeOptions configures a bulk measurement run.
type ProbeOptions struct {
	// Concurrency caps simultaneous tunnels. Keep it modest: the run hits both
	// the provider and a third-party echo service.
	Concurrency int
	// Limit stops after this many slots. Zero means all.
	Limit int
	// Country and City narrow the run.
	Country string
	City    string
	// Slots, when non-empty, restricts the run to these slot IDs. It is applied
	// before Country and City, and is how a previous run's failures are retried.
	Slots []string
	// Interval paces tunnel setup: at most one new tunnel is started per
	// interval. Providers rate-limit handshakes per key, and a fast unpaced sweep
	// of a large bundle will start failing part-way through, so pacing is the
	// difference between measuring the catalog and measuring the rate limiter.
	Interval time.Duration
	// OnResult, when set, is called as each result completes.
	OnResult func(ProbeResult)
}

// Probe brings up each selected slot in turn, measures its public IP, and closes
// it again. It updates the pool's inventory as a side effect.
//
// This is deliberately separate from serving traffic: it is the only reliable way
// to learn how many *distinct* public addresses a bundle really provides, since
// providers routinely share one exit address between many servers.
func (p *Pool) Probe(ctx context.Context, opts ProbeOptions) []ProbeResult {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if p.opts.IPCheckURL == "" {
		return nil
	}

	var wanted map[string]struct{}
	if len(opts.Slots) > 0 {
		wanted = make(map[string]struct{}, len(opts.Slots))
		for _, id := range opts.Slots {
			if id = strings.TrimSpace(id); id != "" {
				wanted[id] = struct{}{}
			}
		}
	}

	p.mu.Lock()
	var targets []*slotState
	for _, id := range p.order {
		state := p.slots[id]
		if wanted != nil {
			if _, ok := wanted[id]; !ok {
				continue
			}
		}
		if opts.Country != "" && !strings.EqualFold(state.spec.Country, opts.Country) {
			continue
		}
		if opts.City != "" && !strings.EqualFold(state.spec.City, opts.City) {
			continue
		}
		targets = append(targets, state)
		if opts.Limit > 0 && len(targets) >= opts.Limit {
			break
		}
	}
	p.mu.Unlock()

	results := make([]ProbeResult, len(targets))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	var pace <-chan time.Time
	if opts.Interval > 0 {
		ticker := time.NewTicker(opts.Interval)
		defer ticker.Stop()
		pace = ticker.C
	}

	for i, state := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(idx int, st *slotState) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			if pace != nil {
				select {
				case <-pace:
				case <-ctx.Done():
					return
				}
			}

			result := ProbeResult{
				Slot:     st.spec.ID,
				Country:  st.spec.Country,
				City:     st.spec.City,
				Endpoint: st.spec.Target(),
			}
			started := time.Now()

			dialer, closer, err := p.probeDialer(ctx, st)
			if err != nil {
				result.Err = err.Error()
			} else {
				ipCtx, cancel := context.WithTimeout(ctx, p.opts.IPCheckTimeout)
				ip, ipErr := FetchPublicIP(ipCtx, dialer, p.opts.IPCheckURL)
				cancel()
				if ipErr != nil {
					result.Err = ipErr.Error()
				} else {
					result.PublicIP = ip.String()
					p.mu.Lock()
					st.publicIP = ip
					st.ipCheckedAt = time.Now()
					st.failures = 0
					st.lastError = ""
					st.disabledUntil = time.Time{}
					p.mu.Unlock()
				}
				if closer != nil {
					closer()
				}
			}
			if result.Err != "" {
				p.mu.Lock()
				st.failures++
				st.lastError = result.Err
				p.mu.Unlock()
			}
			result.Latency = time.Since(started)

			mu.Lock()
			results[idx] = result
			if opts.OnResult != nil {
				opts.OnResult(result)
			}
			mu.Unlock()
		}(i, state)
	}
	wg.Wait()
	return results
}

// inventoryFile is the on-disk shape of the measured inventory.
type inventoryFile struct {
	Version    int                    `json:"version"`
	SavedAt    time.Time              `json:"saved_at"`
	IPCheckURL string                 `json:"ip_check_url,omitempty"`
	Slots      map[string]inventoryIP `json:"slots"`
}

type inventoryIP struct {
	PublicIP  string    `json:"public_ip"`
	CheckedAt time.Time `json:"checked_at"`
}

// SaveInventory persists measured public IPs so a restart does not have to
// re-probe every slot.
func (p *Pool) SaveInventory(path string) error {
	p.mu.Lock()
	file := inventoryFile{
		Version:    1,
		SavedAt:    time.Now(),
		IPCheckURL: p.opts.IPCheckURL,
		Slots:      make(map[string]inventoryIP),
	}
	for id, state := range p.slots {
		if state.publicIP.IsValid() {
			file.Slots[id] = inventoryIP{
				PublicIP:  state.publicIP.String(),
				CheckedAt: state.ipCheckedAt,
			}
		}
	}
	p.mu.Unlock()

	if len(file.Slots) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pool: create state dir: %w", err)
	}
	blob, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return fmt.Errorf("pool: write inventory: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("pool: replace inventory: %w", err)
	}
	return nil
}

// LoadInventory restores previously measured public IPs. A missing file is not
// an error.
func (p *Pool) LoadInventory(path string) (int, error) {
	blob, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("pool: read inventory: %w", err)
	}
	var file inventoryFile
	if err := json.Unmarshal(blob, &file); err != nil {
		return 0, fmt.Errorf("pool: parse inventory: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	restored := 0
	for id, entry := range file.Slots {
		state, ok := p.slots[id]
		if !ok {
			continue
		}
		addr, err := netip.ParseAddr(entry.PublicIP)
		if err != nil {
			continue
		}
		state.publicIP = addr
		state.ipCheckedAt = entry.CheckedAt
		restored++
	}
	return restored, nil
}

// UniquePublicIPs lists the distinct measured public addresses.
func (p *Pool) UniquePublicIPs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := make(map[string]struct{})
	for _, state := range p.slots {
		if state.publicIP.IsValid() {
			seen[state.publicIP.String()] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// Maintain runs periodic housekeeping until ctx is cancelled: expiring sessions,
// closing idle tunnels and refreshing stale public IPs.
func (p *Pool) Maintain(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.housekeep()
		}
	}
}

func (p *Pool) housekeep() {
	now := time.Now()

	p.mu.Lock()
	p.expireLocked(now)
	var idle []*slotState
	if p.opts.IdleTimeout > 0 {
		for _, state := range p.slots {
			if state.spec.Kind != KindWireGuard {
				continue
			}
			if state.isOpen() && state.leases == 0 && !state.lastUsed.IsZero() &&
				now.Sub(state.lastUsed) > p.opts.IdleTimeout {
				idle = append(idle, state)
			}
		}
	}
	for _, state := range idle {
		p.closeLocked(state, "idle")
	}
	// Refresh at most a couple of stale IPs per tick to stay gentle on the echo
	// service.
	var refresh []*slotState
	for _, state := range p.slots {
		if state.ipChecking {
			continue
		}
		if state.spec.Kind == KindWireGuard && !state.isOpen() {
			continue
		}
		if !state.publicIP.IsValid() || now.Sub(state.ipCheckedAt) > p.opts.IPRefreshInterval {
			refresh = append(refresh, state)
			if len(refresh) >= 2 {
				break
			}
		}
	}
	p.mu.Unlock()

	for _, state := range refresh {
		p.maybeCheckIP(state)
	}
}

// probeDialer builds a throwaway dialer for a probe run. The returned closer, when
// non-nil, releases resources the probe created just for this measurement.
//
// WireGuard slots get a dedicated tunnel that is torn down immediately, so a
// sweep does not end up holding hundreds of tunnels open. Relay-socks slots reuse
// the shared entries and have nothing to release.
func (p *Pool) probeDialer(ctx context.Context, state *slotState) (Dialer, func(), error) {
	if state.spec.Kind == KindRelaySocks {
		dialer, _, err := p.dialerForSocksSlot(ctx, state)
		return dialer, nil, err
	}
	tunnel, err := p.openTunnel(ctx, state.spec.WG)
	if err != nil {
		return nil, nil, err
	}
	return tunnel, func() { _ = tunnel.Close() }, nil
}
