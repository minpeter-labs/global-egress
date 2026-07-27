// Package proxy exposes the pool over the two protocols clients already speak:
// SOCKS5 and HTTP (including CONNECT).
//
// Both listeners share the same authorisation, policy parsing, destination
// guarding and relaying logic; only the wire protocol differs.
package proxy

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/minpeter-labs/global-egress/internal/netguard"
	"github.com/minpeter-labs/global-egress/internal/policy"
	"github.com/minpeter-labs/global-egress/internal/pool"
)

// Deps are the shared dependencies of both proxy listeners.
type Deps struct {
	// Pool selects and dials egress slots.
	Pool *pool.Pool
	// Guard vets destinations.
	Guard *netguard.Guard
	// Logger receives per-connection events.
	Logger *slog.Logger
	// AllowedClients restricts who may use the proxy. Empty allows everyone,
	// which is only sensible when the listener is bound to a trusted address.
	AllowedClients []netip.Prefix
	// Password, when set, must be presented by clients. The username carries the
	// selection policy and is never used as an identity.
	Password string
	// RequireAuth rejects clients that present no credentials at all.
	RequireAuth bool
	// DialTimeout bounds establishing the upstream connection.
	DialTimeout time.Duration
	// DialAttempts is how many different slots one request may try before giving
	// up. Individual exits fail routinely, so a retry is normal operation.
	DialAttempts int
	// IdleTimeout closes relayed connections after inactivity. Zero disables it.
	IdleTimeout time.Duration
}

func (d *Deps) applyDefaults() {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.DialTimeout <= 0 {
		d.DialTimeout = 30 * time.Second
	}
	if d.DialAttempts <= 0 {
		d.DialAttempts = 3
	}
}

// errUnauthorized signals a credential problem, which the two protocols report
// differently.
var errUnauthorized = errors.New("proxy: unauthorized")

// checkClient enforces the client ACL.
func (d *Deps) checkClient(remote net.Addr) error {
	if len(d.AllowedClients) == 0 {
		return nil
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("proxy: cannot parse client address %q", remote.String())
	}
	addr = addr.Unmap()
	for _, prefix := range d.AllowedClients {
		if prefix.Addr().Is4() == addr.Is4() && prefix.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("proxy: client %s is not allowed", addr)
}

// authorize validates credentials and extracts the selection policy from the
// username. hadCredentials reports whether the client presented any.
func (d *Deps) authorize(username, password string, hadCredentials bool) (policy.Policy, error) {
	if d.Password != "" {
		if !hadCredentials {
			return policy.Policy{}, errUnauthorized
		}
		if subtle.ConstantTimeCompare([]byte(password), []byte(d.Password)) != 1 {
			return policy.Policy{}, errUnauthorized
		}
	} else if d.RequireAuth && !hadCredentials {
		return policy.Policy{}, errUnauthorized
	}

	pol, err := policy.Parse(username)
	if err != nil {
		return policy.Policy{}, err
	}
	return pol, nil
}

// connectUpstream picks a slot and opens a connection to host:port through it,
// trying other slots when one fails.
func (d *Deps) connectUpstream(ctx context.Context, pol policy.Policy, host string, port int) (net.Conn, *pool.Lease, error) {
	if err := d.Guard.CheckPort(port); err != nil {
		return nil, nil, err
	}
	if err := d.Guard.CheckHost(host); err != nil {
		return nil, nil, err
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))

	var lastErr error
	for attempt := 0; attempt < d.DialAttempts; attempt++ {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		lease, err := d.Pool.Acquire(ctx, pol, host)
		if err != nil {
			if lastErr != nil {
				return nil, nil, lastErr
			}
			return nil, nil, err
		}

		conn, err := d.dialOnce(ctx, lease, address)
		if err == nil {
			return conn, lease, nil
		}
		// Back the slot off and let the next attempt choose another one.
		d.Pool.NoteDialFailure(lease, err)
		lease.Release()
		lastErr = fmt.Errorf("proxy: dial %s via %s: %w", address, lease.Slot.ID, err)
		d.Logger.Debug("egress attempt failed",
			slog.String("target", address),
			slog.String("slot", lease.Slot.ID),
			slog.Int("attempt", attempt+1),
			slog.Any("error", err))
	}
	return nil, nil, lastErr
}

func (d *Deps) dialOnce(ctx context.Context, lease *pool.Lease, address string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, d.DialTimeout)
	defer cancel()

	conn, err := lease.DialContext(dialCtx, "tcp", address)
	if err != nil {
		return nil, err
	}
	// With a direct tunnel the peer address is the destination, so a name that
	// resolved into internal space can still be caught here. Through a proxy the
	// peer address is the proxy itself and the destination is resolved at the
	// exit, so there is nothing local left to verify.
	if !lease.Chained {
		if err := d.Guard.CheckResolved(conn.RemoteAddr()); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// replyCodeFor maps an internal failure to the closest SOCKS5 reply code, so
// clients can distinguish "policy refused this" from "the site is down".
func replyCodeFor(err error) byte {
	switch {
	case err == nil:
		return repSuccess
	case errors.Is(err, pool.ErrNoCandidate), errors.Is(err, pool.ErrCapacity),
		errors.Is(err, pool.ErrTunnelBudget):
		return repNotAllowed
	case errors.Is(err, pool.ErrExhausted):
		return repHostUnreachable
	case errors.Is(err, context.DeadlineExceeded):
		return repHostUnreachable
	}
	if isRefused(err) {
		return repConnectionRefused
	}
	return repGeneralFailure
}

func isRefused(err error) bool {
	var sysErr *net.OpError
	if errors.As(err, &sysErr) {
		return sysErr.Err != nil && strings.Contains(sysErr.Err.Error(), "refused")
	}
	return strings.Contains(err.Error(), "refused")
}

// ipString renders a lease's measured egress IP, or "unknown" before the first
// measurement completes.
func ipString(lease *pool.Lease) string {
	if lease == nil || !lease.PublicIP.IsValid() {
		return "unknown"
	}
	return lease.PublicIP.String()
}

// closeWriter is implemented by TCP-like connections that support half-close,
// including gVisor's netstack connections.
type closeWriter interface {
	CloseWrite() error
}

// relay copies data in both directions until either side finishes, and returns
// the bytes sent from client to upstream and back.
func relay(client, upstream net.Conn, idleTimeout time.Duration) (sent, received int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	copyDir := func(dst, src net.Conn, counter *int64) {
		defer wg.Done()
		n, _ := copyWithIdle(dst, src, idleTimeout)
		*counter = n
		// Signal EOF downstream so the peer can finish cleanly instead of waiting
		// for the whole connection to be torn down.
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.SetReadDeadline(time.Now())
		}
	}

	go copyDir(upstream, client, &sent)
	go copyDir(client, upstream, &received)
	wg.Wait()
	return sent, received
}

// relayBufferSize is the copy chunk for a proxied stream. 32 KiB matches what
// io.Copy uses and is large enough that the per-read deadline bookkeeping is
// negligible.
const relayBufferSize = 32 * 1024

// relayBuffers keeps copy buffers off the heap churn path: a busy proxy opens and
// closes connections constantly, and each one would otherwise allocate 64 KiB.
var relayBuffers = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufferSize)
		return &buf
	},
}

// copyWithIdle copies src into dst, resetting a deadline on every successful
// read so that stalled connections do not accumulate.
func copyWithIdle(dst, src net.Conn, idleTimeout time.Duration) (int64, error) {
	if idleTimeout <= 0 {
		return io.Copy(dst, src)
	}
	bufPtr := relayBuffers.Get().(*[]byte)
	defer relayBuffers.Put(bufPtr)
	buf := *bufPtr
	var total int64
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
		n, readErr := src.Read(buf)
		if n > 0 {
			_ = dst.SetWriteDeadline(time.Now().Add(idleTimeout))
			written, writeErr := dst.Write(buf[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return total, nil
			}
			return total, readErr
		}
	}
}
