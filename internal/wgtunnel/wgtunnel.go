// Package wgtunnel runs a WireGuard tunnel entirely in userspace and exposes it
// as a dialer.
//
// Each tunnel owns a wireguard-go device attached to a gVisor netstack TUN, so
// the process never touches host routing, network namespaces or /dev/net/tun.
// That is what makes it possible to keep hundreds of tunnels up simultaneously
// even though every configuration in a provider bundle claims the same tunnel
// address and a default route.
package wgtunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/minpeter/global-egress/internal/catalog"
)

// DefaultKeepalive keeps the peer session and any NAT mapping alive, and makes
// the device start its handshake as soon as it comes up instead of waiting for
// the first payload packet.
const DefaultKeepalive = 25 * time.Second

// Tunnel is a live userspace WireGuard tunnel.
type Tunnel struct {
	slot catalog.Slot
	dev  *device.Device
	net  *netstack.Net

	closeOnce sync.Once
	closeErr  error
}

// Open brings up a tunnel for the given slot. It does not wait for the
// handshake to complete: WireGuard handshakes lazily and the first dial (or the
// keepalive) triggers it. Use WaitHandshake when readiness matters.
//
// ctx bounds the one-off resolution of the peer endpoint. It is not retained.
func Open(ctx context.Context, slot catalog.Slot, logger *slog.Logger) (*Tunnel, error) {
	if logger == nil {
		logger = slog.Default()
	}

	endpoint, err := resolveEndpoint(ctx, slot.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("wgtunnel %s: %w", slot.ID, err)
	}

	mtu := slot.MTU
	if mtu <= 0 {
		mtu = catalog.DefaultMTU
	}

	tunDev, netStack, err := netstack.CreateNetTUN(slot.Addresses, slot.DNS, mtu)
	if err != nil {
		return nil, fmt.Errorf("wgtunnel %s: create netstack TUN: %w", slot.ID, err)
	}

	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), newDeviceLogger(logger, slot.ID))

	uapi, err := buildUAPI(slot, endpoint)
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel %s: %w", slot.ID, err)
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel %s: configure device: %w", slot.ID, err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wgtunnel %s: bring device up: %w", slot.ID, err)
	}

	return &Tunnel{slot: slot, dev: dev, net: netStack}, nil
}

// Slot returns the specification this tunnel was built from.
func (t *Tunnel) Slot() catalog.Slot { return t.slot }

// DialContext opens a connection through the tunnel. Host names are resolved by
// the resolvers configured for the slot (for Mullvad, 10.64.0.1), so lookups
// happen inside the tunnel and never leak to the host resolver.
func (t *Tunnel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("wgtunnel: unsupported network %q", network)
	}
	return t.net.DialContext(ctx, network, address)
}

// WaitHandshake blocks until the peer has completed a handshake or ctx is done.
func (t *Tunnel) WaitHandshake(ctx context.Context) error {
	const interval = 150 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		ok, err := t.HasHandshake()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wgtunnel %s: no handshake: %w", t.slot.ID, ctx.Err())
		case <-ticker.C:
		}
	}
}

// HasHandshake reports whether the peer has ever completed a handshake.
func (t *Tunnel) HasHandshake() (bool, error) {
	at, err := t.LastHandshake()
	if err != nil {
		return false, err
	}
	return !at.IsZero(), nil
}

// LastHandshake returns the time of the most recent completed handshake, or the
// zero time when none has happened yet.
func (t *Tunnel) LastHandshake() (time.Time, error) {
	var sb strings.Builder
	if err := t.dev.IpcGetOperation(&sb); err != nil {
		return time.Time{}, fmt.Errorf("wgtunnel %s: query device: %w", t.slot.ID, err)
	}
	var secs, nanos int64
	for _, line := range strings.Split(sb.String(), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			secs, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanos, _ = strconv.ParseInt(value, 10, 64)
		}
	}
	if secs == 0 && nanos == 0 {
		return time.Time{}, nil
	}
	return time.Unix(secs, nanos), nil
}

// Close tears the tunnel down. It is safe to call more than once.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		t.dev.Close()
	})
	return t.closeErr
}

func buildUAPI(slot catalog.Slot, endpoint netip.AddrPort) (string, error) {
	privateKey, err := base64ToHex(slot.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid PrivateKey: %w", err)
	}
	peerKey, err := base64ToHex(slot.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("invalid peer PublicKey: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", privateKey)
	// No listen_port: the kernel picks a free ephemeral port per tunnel, which
	// is required when hundreds of tunnels share one process.
	fmt.Fprintf(&sb, "public_key=%s\n", peerKey)
	fmt.Fprintf(&sb, "endpoint=%s\n", endpoint.String())
	fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", int(DefaultKeepalive.Seconds()))
	if slot.PeerPresharedKey != "" {
		psk, err := base64ToHex(slot.PeerPresharedKey)
		if err != nil {
			return "", fmt.Errorf("invalid PresharedKey: %w", err)
		}
		fmt.Fprintf(&sb, "preshared_key=%s\n", psk)
	}
	allowed := slot.AllowedIPs
	if len(allowed) == 0 {
		allowed = []netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"),
			netip.MustParsePrefix("::/0"),
		}
	}
	for _, prefix := range allowed {
		fmt.Fprintf(&sb, "allowed_ip=%s\n", prefix.String())
	}
	return sb.String(), nil
}

// resolveEndpoint turns "host:port" into an AddrPort, resolving names with the
// host resolver. This is the only lookup that happens outside the tunnel, and
// it is unavoidable: it is how we find the tunnel in the first place.
func resolveEndpoint(ctx context.Context, endpoint string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint %q: %w", endpoint, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid endpoint port in %q", endpoint)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(addr, uint16(port)), nil
	}

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve endpoint %q: no addresses", host)
	}
	// Prefer IPv4: provider endpoints are reachable over v4 on every host we
	// target, while v6 egress is not guaranteed.
	for _, addr := range addrs {
		if addr.Unmap().Is4() {
			return netip.AddrPortFrom(addr.Unmap(), uint16(port)), nil
		}
	}
	return netip.AddrPortFrom(addrs[0], uint16(port)), nil
}

// base64ToHex converts a standard base64 WireGuard key to the hex form the
// device UAPI expects.
func base64ToHex(key string) (string, error) {
	raw, err := decodeBase64Key(key)
	if err != nil {
		return "", err
	}
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(raw)*2)
	for _, b := range raw {
		out = append(out, hexDigits[b>>4], hexDigits[b&0x0f])
	}
	return string(out), nil
}
