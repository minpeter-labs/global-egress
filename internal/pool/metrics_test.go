package pool

import (
	"testing"
	"time"
)

func TestObserveRequestRecordsResultAndDuration(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.ObserveRequest(RequestObservation{
		Result:           RequestSuccess,
		RequestedCountry: "jp",
		Lease:            lease,
		Duration:         125 * time.Millisecond,
	})

	snapshot := p.Metrics()
	if len(snapshot.Requests) != 1 {
		t.Fatalf("requests = %+v, want one series", snapshot.Requests)
	}
	request := snapshot.Requests[0]
	if request.Result != RequestSuccess || request.Country != "jp" || request.Entry != "entry-jp" || request.Count != 1 {
		t.Errorf("request = %+v, want successful jp request through entry-jp", request)
	}
	if len(snapshot.RequestDurations) != 1 {
		t.Fatalf("durations = %+v, want one series", snapshot.RequestDurations)
	}
	duration := snapshot.RequestDurations[0]
	if duration.Count != 1 || duration.Sum != 0.125 {
		t.Errorf("duration = %+v, want count=1 sum=0.125", duration)
	}
	if got := duration.Buckets[len(duration.Buckets)-1]; got.UpperBound != "+Inf" || got.Count != 1 {
		t.Errorf("last bucket = %+v, want +Inf=1", got)
	}
}

func TestObserveRequestRecordsRequestedSelectedAndFallbackCountries(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.ObserveRequest(RequestObservation{
		Result:           RequestSuccess,
		RequestedCountry: "us",
		Lease:            lease,
		Duration:         time.Second,
	})

	snapshot := p.Metrics()
	if got := snapshot.RequestedCountries; len(got) != 1 || got[0].Country != "us" || got[0].Count != 1 {
		t.Errorf("requested countries = %+v, want us=1", got)
	}
	if got := snapshot.SelectedCountries; len(got) != 1 || got[0].Country != "jp" || got[0].Count != 1 {
		t.Errorf("selected countries = %+v, want jp=1", got)
	}
	if got := snapshot.CountryFallbacks; len(got) != 1 || got[0].Requested != "us" || got[0].Selected != "jp" || got[0].Count != 1 {
		t.Errorf("fallbacks = %+v, want us->jp=1", got)
	}
}

func TestObserveTunnelOpenRecordsResultAndDuration(t *testing.T) {
	p := newTestPool(t, Options{})

	p.observeTunnelOpen(TunnelRoleEntry, TunnelSuccess, 750*time.Millisecond)
	p.observeTunnelOpen(TunnelRoleEntry, TunnelFailure, 2*time.Second)

	snapshot := p.Metrics()
	if len(snapshot.TunnelOpens) != 2 {
		t.Fatalf("tunnel opens = %+v, want success and failure", snapshot.TunnelOpens)
	}
	if snapshot.TunnelOpens[0].Role != TunnelRoleEntry || snapshot.TunnelOpens[0].Result != TunnelFailure || snapshot.TunnelOpens[0].Count != 1 {
		t.Errorf("first tunnel result = %+v, want entry failure=1", snapshot.TunnelOpens[0])
	}
	if snapshot.TunnelOpens[1].Result != TunnelSuccess || snapshot.TunnelOpens[1].Count != 1 {
		t.Errorf("second tunnel result = %+v, want success=1", snapshot.TunnelOpens[1])
	}
	if len(snapshot.TunnelDurations) != 2 {
		t.Errorf("tunnel durations = %+v, want two result series", snapshot.TunnelDurations)
	}
}

func TestRecordTrafficGroupsPayloadBytesByCountryAndEntry(t *testing.T) {
	p := newTestPool(t, Options{})
	state := p.slots["jp-tyo-wg-001"]
	lease := &Lease{state: state, Slot: state.spec, Entry: "entry-jp"}

	p.RecordTraffic(lease, 128, 256)

	payloads := p.Metrics().Payloads
	if len(payloads) != 1 {
		t.Fatalf("payloads = %+v, want one series", payloads)
	}
	if got := payloads[0]; got.Country != "jp" || got.Entry != "entry-jp" || got.Sent != 128 || got.Received != 256 {
		t.Errorf("payload = %+v, want jp/entry-jp sent=128 received=256", got)
	}
}
