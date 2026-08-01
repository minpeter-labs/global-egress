package nordvpn

import (
	"fmt"
	"net/netip"

	"github.com/minpeter/global-egress/internal/catalog"
)

// NordLynx hands every client the same tunnel address and resolvers; the server
// tells peers apart by key, not by address. They are constants rather than
// configuration because a different value simply does not work.
const tunnelAddress = "10.5.0.2"

var (
	// nordDNS are the resolvers reachable inside the tunnel.
	nordDNS = []netip.Addr{
		netip.MustParseAddr("103.86.96.100"),
		netip.MustParseAddr("103.86.99.100"),
	}
	// defaultRoute sends everything into the tunnel, which is what an egress slot
	// is for.
	defaultRoute = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
)

// Slots turns the usable servers into catalog slots, one per server, using the
// account's NordLynx private key.
//
// The key is the account's whole VPN identity, so it is taken as an argument
// rather than read here: this package never touches the filesystem for it, never
// logs it, and never puts it in an error. Callers that load it from disk are
// responsible for keeping it at 0600.
func (l *List) Slots(privateKey string) ([]catalog.Slot, error) {
	if privateKey == "" {
		return nil, fmt.Errorf("nordvpn: a NordLynx private key is required")
	}

	usable := l.Usable()
	if len(usable) == 0 {
		return nil, fmt.Errorf("nordvpn: server list contains no usable servers")
	}

	address, err := netip.ParseAddr(tunnelAddress)
	if err != nil {
		return nil, fmt.Errorf("nordvpn: invalid tunnel address")
	}

	slots := make([]catalog.Slot, 0, len(usable))
	for _, server := range usable {
		slots = append(slots, catalog.Slot{
			ID:            server.SlotID(),
			Country:       server.Country,
			City:          server.City(),
			PrivateKey:    privateKey,
			Addresses:     []netip.Addr{address},
			DNS:           nordDNS,
			MTU:           catalog.DefaultMTU,
			PeerPublicKey: server.PublicKey,
			Endpoint:      server.Endpoint(),
			AllowedIPs:    defaultRoute,
			Source:        server.Hostname,
		})
	}
	return slots, nil
}

// Bundle wraps the slots in the same shape the catalog loader produces, so the
// rest of the program cannot tell where a bundle came from.
func (l *List) Bundle(privateKey string) (*catalog.Bundle, error) {
	slots, err := l.Slots(privateKey)
	if err != nil {
		return nil, err
	}
	return &catalog.Bundle{Slots: slots, DistinctKeys: 1}, nil
}
