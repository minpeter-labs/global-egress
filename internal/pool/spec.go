package pool

import (
	"context"
	"net"

	"github.com/minpeter-labs/global-egress/internal/catalog"
)

// Dialer is anything that can open a TCP connection, which is all the pool needs
// from a tunnel or a proxy chain.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Kind distinguishes the two ways an egress slot can reach the internet.
type Kind int

const (
	// KindWireGuard is a slot backed by its own WireGuard tunnel. Its exit
	// address is the tunnel's, and using it costs one key association with the
	// provider, which is rate-limited.
	KindWireGuard Kind = iota
	// KindRelaySocks is a slot backed by a provider SOCKS proxy reached through
	// an entry tunnel. Its exit address is the relay's, and using it costs only a
	// TCP connection, so rotation is cheap and does not touch key associations.
	KindRelaySocks
)

func (k Kind) String() string {
	switch k {
	case KindWireGuard:
		return "wireguard"
	case KindRelaySocks:
		return "relay-socks"
	default:
		return "unknown"
	}
}

// Spec describes one selectable egress.
type Spec struct {
	// ID is unique within the pool.
	ID string
	// Country is an ISO-3166-1 alpha-2 code, e.g. "jp".
	Country string
	// City is a "<country>-<city>" label, e.g. "us-lax".
	City string
	// Kind selects how the slot is reached.
	Kind Kind

	// WG carries the tunnel configuration for KindWireGuard.
	WG catalog.Slot
	// SocksAddr is the proxy "host:port" for KindRelaySocks. The name resolves
	// only inside the provider network, so it is dialled through an entry tunnel.
	SocksAddr string
}

// Target returns the address this slot is reached at, for display purposes.
func (s Spec) Target() string {
	if s.Kind == KindRelaySocks {
		return s.SocksAddr
	}
	return s.WG.Endpoint
}

// SpecsFromBundle turns a WireGuard bundle into one slot per configuration. Each
// slot then owns a tunnel, which is the expensive but self-contained mode.
func SpecsFromBundle(bundle *catalog.Bundle) []Spec {
	if bundle == nil {
		return nil
	}
	specs := make([]Spec, 0, len(bundle.Slots))
	for _, slot := range bundle.Slots {
		specs = append(specs, Spec{
			ID:      slot.ID,
			Country: slot.Country,
			City:    slot.City,
			Kind:    KindWireGuard,
			WG:      slot,
		})
	}
	return specs
}

// ExitSpec is everything the pool needs to know about one proxy exit, expressed
// without reference to any particular provider.
//
// Keeping this type here rather than accepting a provider's own struct is what
// stops the pool from depending on a provider package: whoever knows how to talk
// to a provider does the translation.
type ExitSpec struct {
	// ID must be unique within the pool.
	ID string
	// Country is an ISO-3166-1 alpha-2 code. May be empty.
	Country string
	// City is a "<country>-<city>" label. May be empty.
	City string
	// SocksAddr is the proxy "host:port", resolvable through an entry tunnel.
	SocksAddr string
}

// SpecsFromExits turns proxy exits into slots. These slots share the entry
// tunnels, so hundreds of them cost almost nothing.
func SpecsFromExits(exits []ExitSpec) []Spec {
	specs := make([]Spec, 0, len(exits))
	for _, exit := range exits {
		specs = append(specs, Spec{
			ID:        exit.ID,
			Country:   exit.Country,
			City:      exit.City,
			Kind:      KindRelaySocks,
			SocksAddr: exit.SocksAddr,
		})
	}
	return specs
}
