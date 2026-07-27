# global-egress

Give it a WireGuard configuration bundle, get a rotating egress proxy.

`global-egress` reads a provider bundle such as Mullvad's "all servers" zip and
exposes hundreds of exit addresses behind one internal proxy endpoint. Clients
pick a country, pin a sticky session, demand a unique IP per request, or report a
blocked IP and get rotated — all through the proxy username or a small control
API.

```text
internal client
      │  socks5://egress.example.internal:1080
      │  http://egress.example.internal:3128
      ▼
global-egress ── slot selection (country / session / unique / cooldown)
      │
      ├─ entry tunnel (Tokyo) ─┐
      ├─ entry tunnel (Singapore) ─┼─→ SOCKS proxy on any of ~530 relays
      └─ entry tunnel (Los Angeles) ─┘        │
                                              ▼
                                          internet
```

Everything runs in one process. No `wg-quick`, no network namespaces, no
`/dev/net/tun`, no changes to host routing, no root required.

## Two modes, and why the default is what it is

| | `relay-socks` (default) | `wireguard` |
|---|---|---|
| A slot is | a relay's SOCKS proxy, reached through an entry tunnel | its own userspace WireGuard tunnel |
| Exit addresses | ~530, one per relay | one per tunnel |
| Cost of rotating | one TCP connection | one WireGuard handshake |
| Key associations | 2-3 total, long-lived | one per slot |
| Memory for the whole catalog | ~20 MiB | ~850 MiB |

Providers restrict how quickly one device key may associate with new relays.
Measured on a 532-relay bundle: sweeping the catalog as WireGuard tunnels tripped
that limit after 219 relays in under three minutes and the key stopped
handshaking anywhere for hours. `relay-socks` moves rotation off that path
entirely — the key stays on two or three relays, and exits change by opening a
TCP connection to another relay's proxy from inside the tunnel. See
[docs/capacity.md](docs/capacity.md) for the numbers.

`wireguard` mode remains available: it needs no relay list and its exit addresses
are a different set, which is useful if a provider ever stops offering proxies.

## Why not an existing tool

| Tool | What it does | What is missing for this use case |
|---|---|---|
| `wireproxy` | Userspace WireGuard → SOCKS5/HTTP | One tunnel per process; no pool, no selection policy |
| `gluetun` | VPN container with built-in proxy | One tunnel per container; no central selection |
| `sing-box`, `Xray-core`, mihomo | Many WireGuard outbounds + balancing | Rule-based routing, not per-connection slot control; no sticky sessions, unique-IP batches or block reporting |
| `gost` | Upstream proxy load balancing | Does not manage the tunnels themselves |
| `rota`, `slrp` | Rotation control planes | Rotate existing proxy lists, not WireGuard tunnels |

The tunnel part is solved. The control plane — per-connection slot selection,
sticky sessions, verified-unique IPs, per-target cooldowns — is what this project
adds.

## Quick start

```sh
# 1. Import the provider bundle (the .conf files hold a private key).
global-egress import -zip ~/mullvad-all.zip -dir /var/lib/global-egress/wireguard

# 2. See what the bundle contains, without connecting anywhere.
global-egress inspect -catalog /var/lib/global-egress/wireguard

# 3. See the relay list that relay-socks mode exits through.
global-egress relays -cache /var/lib/global-egress/relays.json

# 4. Optional: measure the exit IP of each slot and store an inventory.
#    In wireguard mode, pace it (-interval): providers rate-limit handshakes per
#    device key, and an unpaced sweep starts failing part-way through.
global-egress probe -catalog /var/lib/global-egress/wireguard \
  -state /var/lib/global-egress/inventory.json \
  -concurrency 2 -interval 2s

# 5. Run the service.
cp deploy/config.example.yaml /etc/global-egress/config.yaml
global-egress serve -config /etc/global-egress/config.yaml
```

## Using the proxy

```sh
# Any healthy slot.
curl -x http://egress.example.internal:3128 https://api.example.com/

# Environment variables, which is what most tools expect.
export HTTP_PROXY=http://egress.example.internal:3128
export HTTPS_PROXY=http://egress.example.internal:3128

# SOCKS5 works for anything TCP, not just HTTP.
curl --socks5-hostname egress.example.internal:1080 https://api.example.com/
```

### Controlling the exit IP

The selection policy travels in the **proxy username**, which every HTTP and
SOCKS5 client supports:

```sh
curl -x http://egress.example.internal:3128 --proxy-user 'cc=jp:x'          https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'city=us-lax:x'     https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'sess=job-1;ttl=600:x' https://api.example.com/
curl -x http://egress.example.internal:3128 --proxy-user 'uniq=batch-7:x'    https://api.example.com/
```

| Directive | Meaning |
|---|---|
| `cc=jp` | Restrict to a country. Several: `cc=jp\|us` |
| `city=us-lax` | Restrict to a city |
| `slot=us-lax-wg-001` | Pin one specific slot, mainly for debugging |
| `sess=name` | Sticky: reuse the same exit IP for this session |
| `ttl=600` | Session lifetime in seconds (or `10m`) |
| `uniq=batch` | Never reuse a public IP within this batch |
| `not=1.2.3.4` | Exclude specific public IPs |

Directives are separated by `;` or `,`. An empty username means "no constraints".
The password is a single optional shared secret (`access.password`), not an
identity.

Every response reports the egress that served it:

```text
X-Egress-Slot: jp-tyo-wg-001
X-Egress-Country: jp
X-Egress-City: jp-tyo
X-Egress-IP: 203.0.113.7
X-Egress-Session: job-1
```

### Rotating when a site blocks you

Changing the session name is the simplest rotation. To also make the pool avoid
that IP for that destination, report it:

```sh
curl -X POST http://egress.example.internal:8080/v1/report \
  -H 'Content-Type: application/json' \
  -d '{"session":"job-1","target":"api.example.com","reason":"http_403","cooldown":"30m"}'
```

The pool then:

1. unbinds the session, so the next request picks a different slot, and
2. puts that slot on cooldown **for that destination only** — blocks are usually
   per-site, so the IP stays useful everywhere else.

```python
import requests

EGRESS = "egress.example.internal"
API = f"http://{EGRESS}:8080"

def proxies(session: str) -> dict:
    url = f"http://sess={session};ttl=600:x@{EGRESS}:3128"
    return {"http": url, "https": url}

def fetch(url: str, session: str, attempts: int = 5):
    for _ in range(attempts):
        response = requests.get(url, proxies=proxies(session), timeout=30)
        if response.status_code not in (403, 429):
            return response
        # Tell the pool this exit is burnt for this target, then retry.
        requests.post(f"{API}/v1/report", timeout=10, json={
            "session": session,
            "target": url,
            "reason": f"http_{response.status_code}",
        })
    raise RuntimeError(f"still blocked after {attempts} attempts: {url}")
```

## Control API

Bound to an internal address, optionally protected by a bearer token.

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | Liveness |
| `GET /v1/info` | Version, uptime, slot count |
| `GET /v1/stats` | Open tunnels, unique IPs, sessions, counters |
| `GET /v1/slots` | Inventory; filters: `country`, `city`, `open`, `with_ip`, `limit` |
| `GET /v1/entries` | Entry tunnels and the latency measured through them |
| `GET /v1/ips` | Distinct measured public IPs |
| `GET /v1/whoami?sess=NAME` | Which slot and IP a session currently uses |
| `GET /v1/sessions/NAME` | Same as `whoami`, path form |
| `POST /v1/sessions/NAME/rotate` | Force the next request onto a new slot |
| `DELETE /v1/sessions/NAME` | Same as rotate |
| `POST /v1/report` | Report a block: rotates and applies a cooldown |

## Design notes

**Userspace tunnels.** Every configuration in a provider bundle claims the same
tunnel address and a default route, so several of them cannot coexist in one
network namespace without policy routing tricks. Each tunnel instead gets its own
[gVisor netstack](https://gvisor.dev/) network stack inside the process, which
sidesteps the conflict entirely and needs no privileges.

**Entries are chosen per exit, and the choice is learned.** Every request pays the
trip to its entry tunnel, so the entry matters as much as the exit. A coarse
geographic prior orders entries at startup, then each successful dial feeds a
latency average per (entry, exit country) and measurements override the prior. A
small fraction of requests deliberately try the runner-up so alternatives keep
being measured. `GET /v1/entries` shows what has been learned.

**Two budgets, not one.** `pool.max_active` caps how many tunnels are *up*;
`pool.new_tunnels_per_window` caps how many may be *opened* per window. The second
one matters because providers restrict how fast a single device key may associate
with new relays — the failure mode is the key getting blocked for hours, not a
slow request. Requests served from already-open tunnels never touch it, and
`/v1/stats` exposes `new_tunnels_used` so you can see when rotation is being
slowed down deliberately.

**Lazy tunnels with a budget.** `pool.max_active` caps how many tunnels are up at
once. Tunnels open on demand, idle ones are closed, and the least recently used
one is evicted when the budget is full. Start low, measure, then raise it.

**Slot count is not IP count — verify it.** `global-egress probe` measures the
real exit IP of each slot and stores an inventory, and `uniq=` batches are
enforced against those measured addresses rather than server names. On a 532-slot
Mullvad bundle every reachable slot turned out to have its own address (456
slots, 456 distinct IPs), but that is a property of the provider, not a promise.

**Bulk probing hits provider rate limits.** Sweeping a large bundle quickly gets
the device key throttled, after which every handshake fails for a while. Use
`-interval` and low `-concurrency`, and see [docs/capacity.md](docs/capacity.md)
for the measurements. Serving traffic is unaffected, because tunnels open on
demand under the `max_active` budget.

**DNS stays in the tunnel.** Host names are resolved through the resolvers in the
slot's own configuration (`10.64.0.1` for Mullvad), so lookups never fall back to
the host resolver.

**It is an internet egress, not a pivot.** Private, loopback, link-local, CGNAT
and multicast destinations are refused by default, both before dialling and again
after resolution.

**One provider device.** A downloaded bundle usually shares a single private key
across every server; `inspect` reports how many distinct keys it found. Check
your provider's terms for how many simultaneous connections one device may make.

## Configuration

See [`deploy/config.example.yaml`](deploy/config.example.yaml). Every field is
documented there.

## Development

```sh
make build   # build ./bin/global-egress
make test    # go test ./...
make check   # gofmt check, go vet, tests
make run     # run with config.local.yaml
```

Reference implementations that informed the design are collected separately in
`~/github.com/tmp/global-egress-references`.

## Limitations

- `CONNECT`/TCP only. No SOCKS5 UDP, so QUIC and HTTP/3 clients fall back to TCP.
- IP selection happens per **connection**. A client reusing one keep-alive
  connection keeps the same exit IP; make a new connection (or change `sess=`) to
  move.
- `uniq=` can only guarantee as many distinct IPs as the bundle actually has, and
  only for slots whose IP has been measured.
- Measuring a whole large bundle takes hours, because handshakes must be paced to
  stay under the provider's per-key rate limit.
- In `relay-socks` mode the destination is resolved at the exit relay, so a host
  name that resolves into private space cannot be caught locally. Literal private
  addresses are still refused before dialling.
- Not an anonymity tool. The provider still sees the tunnel, and the service logs
  which slot served which destination.
