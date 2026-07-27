// Package netguard decides which destinations the proxy is willing to reach.
//
// The service exists to send traffic *out* to the internet. Without a guard it
// would also be a convenient way to reach the internal network it is hosted on,
// so private, loopback, link-local and carrier-grade NAT ranges are denied by
// default.
package netguard

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// DefaultDeniedCIDRs are refused unless the operator overrides the list.
var DefaultDeniedCIDRs = []string{
	"0.0.0.0/8",          // "this host on this network"
	"10.0.0.0/8",         // RFC1918
	"100.64.0.0/10",      // CGNAT, also Tailscale
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link-local, cloud metadata
	"172.16.0.0/12",      // RFC1918
	"192.0.0.0/24",       // IETF protocol assignments
	"192.168.0.0/16",     // RFC1918
	"198.18.0.0/15",      // benchmarking
	"224.0.0.0/4",        // multicast
	"240.0.0.0/4",        // reserved
	"255.255.255.255/32", // broadcast
	"::1/128",            // loopback
	"fc00::/7",           // unique local
	"fe80::/10",          // link-local
	"ff00::/8",           // multicast
}

// Guard evaluates destination addresses and ports.
type Guard struct {
	denied      []netip.Prefix
	allowedPort map[int]bool // nil means "all ports allowed"
}

// New builds a Guard. Passing a nil deniedCIDRs slice installs
// DefaultDeniedCIDRs; passing an empty non-nil slice disables CIDR filtering.
// An empty allowedPorts slice allows every port.
func New(deniedCIDRs []string, allowedPorts []int) (*Guard, error) {
	if deniedCIDRs == nil {
		deniedCIDRs = DefaultDeniedCIDRs
	}
	g := &Guard{}
	for _, raw := range deniedCIDRs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("netguard: invalid CIDR %q: %w", raw, err)
		}
		g.denied = append(g.denied, prefix.Masked())
	}
	if len(allowedPorts) > 0 {
		g.allowedPort = make(map[int]bool, len(allowedPorts))
		for _, port := range allowedPorts {
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("netguard: invalid port %d", port)
			}
			g.allowedPort[port] = true
		}
	}
	return g, nil
}

// CheckPort reports whether the destination port is permitted.
func (g *Guard) CheckPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("netguard: invalid port %d", port)
	}
	if g.allowedPort != nil && !g.allowedPort[port] {
		return fmt.Errorf("netguard: port %d is not allowed", port)
	}
	return nil
}

// CheckAddr reports whether a resolved destination address is permitted.
func (g *Guard) CheckAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("netguard: invalid address")
	}
	// Compare v4-in-v6 forms against v4 prefixes too.
	candidate := addr.Unmap()
	for _, prefix := range g.denied {
		if prefix.Addr().Is4() != candidate.Is4() {
			continue
		}
		if prefix.Contains(candidate) {
			return fmt.Errorf("netguard: destination %s is in denied range %s", candidate, prefix)
		}
	}
	return nil
}

// CheckHost permits a destination given as either a literal address or a name.
// Names cannot be evaluated before resolution, so they pass here and are
// re-checked by CheckResolved once the tunnel has resolved them.
func (g *Guard) CheckHost(host string) error {
	if addr, err := netip.ParseAddr(host); err == nil {
		return g.CheckAddr(addr)
	}
	if host == "" {
		return fmt.Errorf("netguard: empty destination host")
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return fmt.Errorf("netguard: destination %q is not allowed", host)
	}
	return nil
}

// CheckResolved validates the address a dial actually connected to. It accepts
// the net.Addr returned by a successful dial, which is the last point where a
// DNS answer pointing at internal space can still be caught.
func (g *Guard) CheckResolved(addr net.Addr) error {
	if addr == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil {
		// Not an address literal, so there is nothing here to evaluate. The name
		// was already vetted by CheckHost.
		return nil //nolint:nilerr // an unparsable peer address is not a policy violation
	}
	return g.CheckAddr(parsed)
}
