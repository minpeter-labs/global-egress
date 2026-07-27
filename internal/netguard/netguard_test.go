package netguard

import (
	"net"
	"net/netip"
	"testing"
)

func TestDefaultDeniesInternalRanges(t *testing.T) {
	guard, err := New(nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	denied := []string{
		"10.10.10.1",      // RFC1918: the network this service is hosted on
		"192.168.0.120",   // RFC1918
		"172.16.5.5",      // RFC1918
		"127.0.0.1",       // loopback
		"169.254.169.254", // cloud metadata
		"100.119.184.70",  // CGNAT / Tailscale
		"::1",             // IPv6 loopback
		"fd7a:115c:a1e0::1",
	}
	for _, raw := range denied {
		addr := netip.MustParseAddr(raw)
		if err := guard.CheckAddr(addr); err == nil {
			t.Errorf("CheckAddr(%s) allowed an internal address", raw)
		}
	}

	allowed := []string{"1.1.1.1", "146.70.199.219", "23.234.101.88", "2606:4700::1111"}
	for _, raw := range allowed {
		addr := netip.MustParseAddr(raw)
		if err := guard.CheckAddr(addr); err != nil {
			t.Errorf("CheckAddr(%s) = %v, want allowed", raw, err)
		}
	}
}

func TestCheckAddrHandlesV4MappedV6(t *testing.T) {
	guard, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// ::ffff:10.0.0.1 must be treated as the IPv4 address it encodes.
	addr := netip.MustParseAddr("::ffff:10.0.0.1")
	if err := guard.CheckAddr(addr); err == nil {
		t.Error("v4-mapped RFC1918 address was allowed")
	}
}

func TestCheckHost(t *testing.T) {
	guard, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckHost("example.com"); err != nil {
		t.Errorf("CheckHost(example.com) = %v, want allowed pending resolution", err)
	}
	if err := guard.CheckHost("10.0.0.5"); err == nil {
		t.Error("CheckHost(10.0.0.5) allowed a literal internal address")
	}
	if err := guard.CheckHost("localhost"); err == nil {
		t.Error("CheckHost(localhost) allowed loopback by name")
	}
	if err := guard.CheckHost(""); err == nil {
		t.Error("CheckHost(\"\") allowed an empty host")
	}
}

func TestCheckResolved(t *testing.T) {
	guard, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	internal := &net.TCPAddr{IP: net.ParseIP("192.168.1.10"), Port: 80}
	if err := guard.CheckResolved(internal); err == nil {
		t.Error("CheckResolved allowed an internal address")
	}
	external := &net.TCPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	if err := guard.CheckResolved(external); err != nil {
		t.Errorf("CheckResolved(1.1.1.1) = %v", err)
	}
	if err := guard.CheckResolved(nil); err != nil {
		t.Errorf("CheckResolved(nil) = %v, want nil", err)
	}
}

func TestPortAllowlist(t *testing.T) {
	guard, err := New(nil, []int{80, 443})
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckPort(443); err != nil {
		t.Errorf("CheckPort(443) = %v", err)
	}
	if err := guard.CheckPort(22); err == nil {
		t.Error("CheckPort(22) allowed a port outside the allowlist")
	}
	if err := guard.CheckPort(0); err == nil {
		t.Error("CheckPort(0) allowed an invalid port")
	}

	open, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := open.CheckPort(22); err != nil {
		t.Errorf("with no allowlist, CheckPort(22) = %v, want allowed", err)
	}
}

func TestEmptyDenylistDisablesFiltering(t *testing.T) {
	guard, err := New([]string{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckAddr(netip.MustParseAddr("10.0.0.1")); err != nil {
		t.Errorf("an explicitly empty denylist should allow everything, got %v", err)
	}
}

func TestNewRejectsBadCIDR(t *testing.T) {
	if _, err := New([]string{"not-a-cidr"}, nil); err == nil {
		t.Fatal("expected an error for an invalid CIDR")
	}
	if _, err := New(nil, []int{99999}); err == nil {
		t.Fatal("expected an error for an invalid port")
	}
}
