package pool

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/minpeter-labs/global-egress/internal/catalog"
	"github.com/minpeter-labs/global-egress/internal/georoute"
	"github.com/minpeter-labs/global-egress/internal/socksdial"
	"github.com/minpeter-labs/global-egress/internal/wgtunnel"
)

// entryState is one long-lived WireGuard tunnel used as an entry point for relay
// SOCKS slots.
//
// Entries are the only thing that costs a key association, so there are few of
// them and they stay up. Everything else rides on top.
type entryState struct {
	spec catalog.Slot

	tunnel  *wgtunnel.Tunnel
	opening chan struct{}

	failures      int
	lastError     string
	disabledUntil time.Time
	openedAt      time.Time

	// latency holds an exponentially weighted moving average of how long it took
	// to reach exits in a given country through this entry, plus the sample count.
	// Real traffic feeds this, so routing improves without extra probing.
	latency map[string]time.Duration
	samples map[string]int
}

// ewmaAlpha weights new latency samples. 0.3 reacts within a handful of requests
// without letting one slow connection dominate.
const ewmaAlpha = 0.3

// priorLatency converts a geographic prior into a pseudo-latency so that
// unmeasured entries can be ordered against measured ones. The unit is arbitrary
// but the scale is deliberately pessimistic: a real measurement almost always
// looks better than a guess, which is what we want.
const priorLatencyPerHop = 250 * time.Millisecond

func (e *entryState) score(exitCountry string) time.Duration {
	if measured, ok := e.latency[exitCountry]; ok {
		return measured
	}
	hops := georoute.Cost(e.spec.Country, exitCountry)
	return time.Duration(hops+1) * priorLatencyPerHop
}

func (e *entryState) isOpen() bool { return e.tunnel != nil }

// EntryInfo is the public view of an entry tunnel.
type EntryInfo struct {
	ID       string `json:"id"`
	Country  string `json:"country,omitempty"`
	City     string `json:"city,omitempty"`
	Endpoint string `json:"endpoint"`
	Region   string `json:"region,omitempty"`

	Open      bool       `json:"open"`
	OpenedAt  *time.Time `json:"opened_at,omitempty"`
	Failures  int        `json:"failures,omitempty"`
	LastError string     `json:"last_error,omitempty"`

	// Latency lists the measured average per exit country, in milliseconds.
	Latency map[string]int64 `json:"latency_ms,omitempty"`
}

// Entries returns a snapshot of the entry tunnels and what has been learned about
// them.
func (p *Pool) Entries() []EntryInfo {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]EntryInfo, 0, len(p.entries))
	for _, entry := range p.entries {
		info := EntryInfo{
			ID:        entry.spec.ID,
			Country:   entry.spec.Country,
			City:      entry.spec.City,
			Endpoint:  entry.spec.Endpoint,
			Region:    string(georoute.RegionOf(entry.spec.Country)),
			Open:      entry.isOpen(),
			Failures:  entry.failures,
			LastError: entry.lastError,
		}
		if !entry.openedAt.IsZero() {
			at := entry.openedAt
			info.OpenedAt = &at
		}
		if len(entry.latency) > 0 {
			info.Latency = make(map[string]int64, len(entry.latency))
			for country, d := range entry.latency {
				info.Latency[country] = d.Milliseconds()
			}
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// orderedEntriesLocked returns healthy entries, best first, for reaching an exit
// in exitCountry.
func (p *Pool) orderedEntriesLocked(exitCountry string, now time.Time) []*entryState {
	candidates := make([]*entryState, 0, len(p.entries))
	for _, entry := range p.entries {
		if now.Before(entry.disabledUntil) {
			continue
		}
		candidates = append(candidates, entry)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		si, sj := candidates[i].score(exitCountry), candidates[j].score(exitCountry)
		if si != sj {
			return si < sj
		}
		// Prefer an entry that is already up: it saves a handshake.
		if candidates[i].isOpen() != candidates[j].isOpen() {
			return candidates[i].isOpen()
		}
		return candidates[i].spec.ID < candidates[j].spec.ID
	})

	// Occasionally try the runner-up so alternatives keep getting measured;
	// otherwise the first entry that happens to look good is never challenged.
	if len(candidates) > 1 && p.rng.Float64() < p.opts.EntryExploreRate {
		candidates[0], candidates[1] = candidates[1], candidates[0]
	}
	return candidates
}

// recordEntryLatency folds one observation into an entry's moving average.
func (p *Pool) recordEntryLatency(entry *entryState, exitCountry string, observed time.Duration) {
	if exitCountry == "" || observed <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if entry.latency == nil {
		entry.latency = make(map[string]time.Duration)
		entry.samples = make(map[string]int)
	}
	previous, seen := entry.latency[exitCountry]
	if !seen {
		entry.latency[exitCountry] = observed
	} else {
		entry.latency[exitCountry] = time.Duration(
			ewmaAlpha*float64(observed) + (1-ewmaAlpha)*float64(previous))
	}
	entry.samples[exitCountry]++
}

// ensureEntryOpen brings an entry tunnel up, or returns the live one. Only one
// caller opens a given entry; others wait for it.
func (p *Pool) ensureEntryOpen(ctx context.Context, entry *entryState) (*wgtunnel.Tunnel, error) {
	for {
		p.mu.Lock()
		if entry.tunnel != nil {
			tunnel := entry.tunnel
			p.mu.Unlock()
			return tunnel, nil
		}
		if waiting := entry.opening; waiting != nil {
			p.mu.Unlock()
			select {
			case <-waiting:
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if !p.tunnelBudgetAvailableLocked(time.Now()) {
			p.mu.Unlock()
			return nil, ErrTunnelBudget
		}
		done := make(chan struct{})
		entry.opening = done
		spec := entry.spec
		p.mu.Unlock()

		tunnel, err := p.openTunnel(ctx, spec)

		p.mu.Lock()
		entry.opening = nil
		if err == nil {
			entry.tunnel = tunnel
			entry.openedAt = time.Now()
			entry.failures = 0
			entry.lastError = ""
		} else {
			entry.failures++
			entry.lastError = err.Error()
			backoff := p.opts.FailureBackoff << min(entry.failures-1, 5)
			if maxBackoff := 10 * time.Minute; backoff > maxBackoff {
				backoff = maxBackoff
			}
			entry.disabledUntil = time.Now().Add(backoff)
		}
		p.mu.Unlock()
		close(done)

		if err != nil {
			p.log.Warn("entry tunnel failed",
				slog.String("entry", spec.ID),
				slog.Int("failures", entry.failures),
				slog.Any("error", err))
			return nil, err
		}
		p.log.Info("entry tunnel up",
			slog.String("entry", spec.ID),
			slog.String("country", spec.Country))
		return tunnel, nil
	}
}

// dialerForSocksSlot builds a dialer that reaches the slot's SOCKS proxy through
// the best available entry, and reports the observed latency back so future
// choices improve.
func (p *Pool) dialerForSocksSlot(ctx context.Context, state *slotState) (Dialer, string, error) {
	p.mu.Lock()
	candidates := p.orderedEntriesLocked(state.spec.Country, time.Now())
	p.mu.Unlock()

	if len(candidates) == 0 {
		return nil, "", fmt.Errorf("%w: no healthy entry tunnel", ErrExhausted)
	}

	var lastErr error
	for _, entry := range candidates {
		tunnel, err := p.ensureEntryOpen(ctx, entry)
		if err != nil {
			lastErr = err
			continue
		}
		exitCountry := state.spec.Country
		dialer := &measuringDialer{
			inner: &socksdial.Dialer{
				Base:      tunnel,
				ProxyAddr: state.spec.SocksAddr,
				Timeout:   p.opts.HandshakeTimeout,
			},
			observe: func(d time.Duration) { p.recordEntryLatency(entry, exitCountry, d) },
		}
		return dialer, entry.spec.ID, nil
	}
	if lastErr != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrExhausted, lastErr)
	}
	return nil, "", ErrExhausted
}

// measuringDialer times each successful dial. The SOCKS negotiation traverses the
// whole path we care about, so this is a free measurement of entry quality.
type measuringDialer struct {
	inner   Dialer
	observe func(time.Duration)
}

func (m *measuringDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	started := time.Now()
	conn, err := m.inner.DialContext(ctx, network, address)
	if err == nil && m.observe != nil {
		m.observe(time.Since(started))
	}
	return conn, err
}

// closeEntriesLocked tears down every entry tunnel.
func (p *Pool) closeEntriesLocked(reason string) {
	for _, entry := range p.entries {
		if entry.tunnel == nil {
			continue
		}
		tunnel := entry.tunnel
		entry.tunnel = nil
		id := entry.spec.ID
		p.log.Debug("closing entry tunnel", slog.String("entry", id), slog.String("reason", reason))
		go func() {
			if err := tunnel.Close(); err != nil {
				p.log.Warn("entry close failed", slog.String("entry", id), slog.Any("error", err))
			}
		}()
	}
}
