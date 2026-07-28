package pool

import (
	"sort"
	"strconv"
)

// MetricBucket is one cumulative histogram bucket.
type MetricBucket struct {
	UpperBound string
	Count      uint64
}

// RequestMetric is one request counter series.
type RequestMetric struct {
	Result  RequestResult
	Country string
	Entry   string
	Count   uint64
}

// RequestDurationMetric is one request-duration histogram series.
type RequestDurationMetric struct {
	Result  RequestResult
	Country string
	Entry   string
	Buckets []MetricBucket
	Sum     float64
	Count   uint64
}

// CountryMetric is one country counter series.
type CountryMetric struct {
	Country string
	Count   uint64
}

// CountryFallbackMetric is one requested-to-selected country fallback series.
type CountryFallbackMetric struct {
	Requested string
	Selected  string
	Count     uint64
}

// PayloadMetric is one country-and-entry payload counter pair.
type PayloadMetric struct {
	Country  string
	Entry    string
	Sent     uint64
	Received uint64
}

// TunnelMetric is one tunnel-open counter series.
type TunnelMetric struct {
	Role   TunnelRole
	Result TunnelResult
	Count  uint64
}

// TunnelDurationMetric is one tunnel-open-duration histogram series.
type TunnelDurationMetric struct {
	Role    TunnelRole
	Result  TunnelResult
	Buckets []MetricBucket
	Sum     float64
	Count   uint64
}

// MetricsSnapshot is a deterministic copy of process-lifetime proxy metrics.
type MetricsSnapshot struct {
	Requests           []RequestMetric
	RequestDurations   []RequestDurationMetric
	RequestedCountries []CountryMetric
	SelectedCountries  []CountryMetric
	CountryFallbacks   []CountryFallbackMetric
	Payloads           []PayloadMetric
	TunnelOpens        []TunnelMetric
	TunnelDurations    []TunnelDurationMetric
}

// Metrics returns a deterministic process-lifetime metrics snapshot.
func (p *Pool) Metrics() MetricsSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()

	var snapshot MetricsSnapshot
	for key, count := range p.metrics.requests {
		snapshot.Requests = append(snapshot.Requests, RequestMetric{
			Result: key.result, Country: key.country, Entry: key.entry, Count: count,
		})
	}
	sort.Slice(snapshot.Requests, func(i, j int) bool {
		a, b := snapshot.Requests[i], snapshot.Requests[j]
		return a.Result < b.Result ||
			a.Result == b.Result && (a.Country < b.Country ||
				a.Country == b.Country && a.Entry < b.Entry)
	})

	for key, histogram := range p.metrics.requestDurations {
		snapshot.RequestDurations = append(snapshot.RequestDurations, RequestDurationMetric{
			Result: key.result, Country: key.country, Entry: key.entry,
			Buckets: snapshotBuckets(requestDurationBuckets, histogram),
			Sum:     histogram.sum, Count: histogram.count,
		})
	}
	sort.Slice(snapshot.RequestDurations, func(i, j int) bool {
		a, b := snapshot.RequestDurations[i], snapshot.RequestDurations[j]
		return a.Result < b.Result ||
			a.Result == b.Result && (a.Country < b.Country ||
				a.Country == b.Country && a.Entry < b.Entry)
	})

	snapshot.RequestedCountries = snapshotCountries(p.metrics.requestedCountries)
	snapshot.SelectedCountries = snapshotCountries(p.metrics.selectedCountries)
	for key, count := range p.metrics.fallbacks {
		snapshot.CountryFallbacks = append(snapshot.CountryFallbacks, CountryFallbackMetric{
			Requested: key.requested, Selected: key.selected, Count: count,
		})
	}
	sort.Slice(snapshot.CountryFallbacks, func(i, j int) bool {
		a, b := snapshot.CountryFallbacks[i], snapshot.CountryFallbacks[j]
		return a.Requested < b.Requested ||
			a.Requested == b.Requested && a.Selected < b.Selected
	})

	for key, totals := range p.metrics.payloads {
		snapshot.Payloads = append(snapshot.Payloads, PayloadMetric{
			Country: key.country, Entry: key.entry,
			Sent: totals.sent, Received: totals.received,
		})
	}
	sort.Slice(snapshot.Payloads, func(i, j int) bool {
		a, b := snapshot.Payloads[i], snapshot.Payloads[j]
		return a.Country < b.Country || a.Country == b.Country && a.Entry < b.Entry
	})

	for key, count := range p.metrics.tunnelOpens {
		snapshot.TunnelOpens = append(snapshot.TunnelOpens, TunnelMetric{
			Role: key.role, Result: key.result, Count: count,
		})
	}
	sort.Slice(snapshot.TunnelOpens, func(i, j int) bool {
		a, b := snapshot.TunnelOpens[i], snapshot.TunnelOpens[j]
		return a.Role < b.Role || a.Role == b.Role && a.Result < b.Result
	})
	for key, histogram := range p.metrics.tunnelDurations {
		snapshot.TunnelDurations = append(snapshot.TunnelDurations, TunnelDurationMetric{
			Role: key.role, Result: key.result,
			Buckets: snapshotBuckets(tunnelDurationBuckets, histogram),
			Sum:     histogram.sum, Count: histogram.count,
		})
	}
	sort.Slice(snapshot.TunnelDurations, func(i, j int) bool {
		a, b := snapshot.TunnelDurations[i], snapshot.TunnelDurations[j]
		return a.Role < b.Role || a.Role == b.Role && a.Result < b.Result
	})
	return snapshot
}

func snapshotCountries(source map[string]uint64) []CountryMetric {
	out := make([]CountryMetric, 0, len(source))
	for country, count := range source {
		out = append(out, CountryMetric{Country: country, Count: count})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Country < out[j].Country })
	return out
}

func snapshotBuckets(bounds []float64, histogram *histogramMetric) []MetricBucket {
	out := make([]MetricBucket, 0, len(histogram.buckets))
	for i, count := range histogram.buckets {
		upperBound := "+Inf"
		if i < len(bounds) {
			upperBound = strconv.FormatFloat(bounds[i], 'g', -1, 64)
		}
		out = append(out, MetricBucket{UpperBound: upperBound, Count: count})
	}
	return out
}
