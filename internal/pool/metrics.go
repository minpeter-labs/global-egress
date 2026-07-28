package pool

import (
	"strings"
	"time"
)

// RequestResult is a bounded proxy request outcome label.
type RequestResult string

const (
	RequestSuccess         RequestResult = "success"
	RequestBusy            RequestResult = "busy"
	RequestNoCandidate     RequestResult = "no_candidate"
	RequestDialFailure     RequestResult = "dial_failure"
	RequestUpstreamFailure RequestResult = "upstream_failure"
	RequestTimeout         RequestResult = "timeout"
)

// TunnelRole identifies a bounded class of WireGuard tunnel.
type TunnelRole string

const (
	TunnelRoleEntry  TunnelRole = "entry"
	TunnelRoleDirect TunnelRole = "direct"
)

// TunnelResult is a bounded tunnel-open outcome label.
type TunnelResult string

const (
	TunnelSuccess TunnelResult = "success"
	TunnelFailure TunnelResult = "failure"
)

var (
	requestDurationBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	tunnelDurationBuckets  = []float64{0.1, 0.25, 0.5, 1, 2, 3, 5, 8, 12, 20, 30}
)

type requestMetricKey struct {
	result  RequestResult
	country string
	entry   string
}

type fallbackMetricKey struct {
	requested string
	selected  string
}

type payloadMetricKey struct {
	country string
	entry   string
}

type tunnelMetricKey struct {
	role   TunnelRole
	result TunnelResult
}

type histogramMetric struct {
	buckets []uint64
	sum     float64
	count   uint64
}

func (h *histogramMetric) observe(bounds []float64, value float64) {
	if h.buckets == nil {
		h.buckets = make([]uint64, len(bounds)+1)
	}
	for i, bound := range bounds {
		if value <= bound {
			h.buckets[i]++
		}
	}
	h.buckets[len(bounds)]++
	h.sum += value
	h.count++
}

type payloadTotals struct {
	sent     uint64
	received uint64
}

type metricsState struct {
	requests           map[requestMetricKey]uint64
	requestDurations   map[requestMetricKey]*histogramMetric
	requestedCountries map[string]uint64
	selectedCountries  map[string]uint64
	fallbacks          map[fallbackMetricKey]uint64
	payloads           map[payloadMetricKey]payloadTotals
	tunnelOpens        map[tunnelMetricKey]uint64
	tunnelDurations    map[tunnelMetricKey]*histogramMetric
}

func (m *metricsState) ensure() {
	if m.requests != nil {
		return
	}
	m.requests = make(map[requestMetricKey]uint64)
	m.requestDurations = make(map[requestMetricKey]*histogramMetric)
	m.requestedCountries = make(map[string]uint64)
	m.selectedCountries = make(map[string]uint64)
	m.fallbacks = make(map[fallbackMetricKey]uint64)
	m.payloads = make(map[payloadMetricKey]payloadTotals)
	m.tunnelOpens = make(map[tunnelMetricKey]uint64)
	m.tunnelDurations = make(map[tunnelMetricKey]*histogramMetric)
}

// RequestObservation describes one completed proxy setup attempt.
type RequestObservation struct {
	Result           RequestResult
	RequestedCountry string
	Lease            *Lease
	Duration         time.Duration
}

// ObserveRequest records one bounded request outcome and setup duration.
func (p *Pool) ObserveRequest(observation RequestObservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.ensure()

	requested := normalizeMetricLabel(observation.RequestedCountry, "any")
	country, entry := leaseMetricLabels(observation.Lease)
	key := requestMetricKey{result: observation.Result, country: country, entry: entry}
	p.metrics.requests[key]++
	histogram := p.metrics.requestDurations[key]
	if histogram == nil {
		histogram = &histogramMetric{}
		p.metrics.requestDurations[key] = histogram
	}
	histogram.observe(requestDurationBuckets, observation.Duration.Seconds())
	p.metrics.requestedCountries[requested]++
	if observation.Lease != nil {
		p.metrics.selectedCountries[country]++
		if isCountryCode(requested) && requested != country {
			p.metrics.fallbacks[fallbackMetricKey{requested: requested, selected: country}]++
		}
	}
}

func (p *Pool) observeTunnelOpen(role TunnelRole, result TunnelResult, duration time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics.ensure()
	key := tunnelMetricKey{role: role, result: result}
	p.metrics.tunnelOpens[key]++
	histogram := p.metrics.tunnelDurations[key]
	if histogram == nil {
		histogram = &histogramMetric{}
		p.metrics.tunnelDurations[key] = histogram
	}
	histogram.observe(tunnelDurationBuckets, duration.Seconds())
}

func (p *Pool) recordPayloadLocked(lease *Lease, sent, received int64) {
	p.metrics.ensure()
	country, entry := leaseMetricLabels(lease)
	key := payloadMetricKey{country: country, entry: entry}
	totals := p.metrics.payloads[key]
	if sent > 0 {
		totals.sent += uint64(sent)
	}
	if received > 0 {
		totals.received += uint64(received)
	}
	p.metrics.payloads[key] = totals
}

func leaseMetricLabels(lease *Lease) (string, string) {
	if lease == nil {
		return "unknown", "none"
	}
	country := normalizeMetricLabel(lease.Slot.Country, "unknown")
	entry := normalizeMetricLabel(lease.Entry, "direct")
	return country, entry
}

func normalizeMetricLabel(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return fallback
	}
	return value
}

func isCountryCode(value string) bool {
	if len(value) != 2 {
		return false
	}
	for _, r := range value {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}
