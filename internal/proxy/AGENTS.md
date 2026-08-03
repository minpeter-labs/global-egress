# internal/proxy

SOCKS5 and HTTP (incl. CONNECT) listeners over the same pool. `proxy.go` holds the
shared path (ACL, auth, policy, guard, dial retry, relay); the two protocol files
only do wire format.

## WHERE TO LOOK

| Task | File |
|---|---|
| ACL, auth, `connectUpstream`, `relay`/`copyWithIdle` | `proxy.go` |
| CONNECT metadata, header hygiene, status mapping | `http.go` |
| SOCKS5 handshake and reply codes | `socks5.go` |
| Per-request observation feeding `pool` counters | `metrics.go` |

## INVARIANTS

- `X-Egress-*` is a reserved namespace. Those headers are stripped from requests
  and origin responses in both directions (`stripEgressHeaders`,
  `copyForwardResponseHeaders`) and only ever written on a successful CONNECT
  reply. Never let an origin response carry them.
- CONNECT headers are serialized by hand after hijack, so every dynamic value
  passes `validHeaderValue` first. Catalog metadata or a crafted policy would
  otherwise allow response splitting.
- `Proxy-Authorization` only. `Authorization` is deliberately not a fallback: on
  plain HTTP it belongs to the origin and must be forwarded unchanged.
- `CheckResolved` guards two dial paths, both behind `!lease.Chained`:
  `proxy.go` `dialOnce` (CONNECT and SOCKS5) and the per-request
  `http.Transport.DialContext` in `http.go` for plain HTTP forwarding. A new dial
  path needs its own call. The `Chained` condition is not laziness: through a relay
  proxy the peer address is the proxy and the destination resolves at the exit, so
  nothing local is left to verify.
- Every pool sentinel maps to a code in exactly two places: `statusCodeFor`
  (`http.go`) and `replyCodeFor` (`proxy.go`). A new `pool.Err*` needs both.
- Dial failures back the slot off (`NoteDialFailure`) and retry another slot up to
  `DialAttempts`. Individual exits failing is normal operation, not an error path.

## CONVENTIONS

- Logs carry `error_type` (`%T`) and `policy` via `pol.LogString()`, never client
  addresses, destinations or excluded IPs. HTTP error bodies stay generic.
- Relay copy buffers come from `relayBuffers` (`sync.Pool`, 32 KiB); a busy proxy
  would otherwise churn 64 KiB per connection.
- Half-close is signalled through `closeWriter` (netstack conns implement it),
  falling back to a past read deadline.
