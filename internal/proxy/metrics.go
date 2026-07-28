package proxy

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/minpeter/global-egress/internal/policy"
	"github.com/minpeter/global-egress/internal/pool"
)

func (d *Deps) observeRequest(
	pol policy.Policy,
	lease *pool.Lease,
	result pool.RequestResult,
	duration time.Duration,
) {
	if d.Pool == nil {
		return
	}
	d.Pool.ObserveRequest(pool.RequestObservation{
		Result:           result,
		RequestedCountry: requestedCountry(pol),
		Lease:            lease,
		Duration:         duration,
	})
}

func requestedCountry(pol policy.Policy) string {
	switch len(pol.Countries) {
	case 0:
		return "any"
	case 1:
		return strings.ToLower(pol.Countries[0])
	default:
		return "multiple"
	}
}

func requestResult(err error) pool.RequestResult {
	switch {
	case err == nil:
		return pool.RequestSuccess
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return pool.RequestTimeout
	case errors.Is(err, pool.ErrBusy), errors.Is(err, pool.ErrTunnelBudget):
		return pool.RequestBusy
	case errors.Is(err, pool.ErrNoCandidate), errors.Is(err, pool.ErrExhausted):
		return pool.RequestNoCandidate
	default:
		return pool.RequestDialFailure
	}
}

func upstreamResult(err error) pool.RequestResult {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return pool.RequestTimeout
	}
	return pool.RequestUpstreamFailure
}
