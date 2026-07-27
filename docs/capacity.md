# Capacity

Measured on 2026-07-28 with a 532-slot Mullvad bundle, Go 1.26, Linux, one
`global-egress` process.

## Memory

| State | RSS |
|---|---:|
| 532 slots parsed, 0 tunnels open | 14.8 MiB |
| 532 slots parsed, 30 tunnels open | 61.8 MiB |
| **Cost per open tunnel** | **≈1.57 MiB** |

Projection from those two points:

| Open tunnels | Projected RSS |
|---:|---:|
| 25 | ~54 MiB |
| 100 | ~171 MiB |
| 250 | ~406 MiB |
| 532 (all) | ~848 MiB |

Loading the catalog is cheap; only *open* tunnels cost memory. `pool.max_active`
is therefore the knob that decides the footprint.

## Other per-tunnel resources

With 30 tunnels open the process used:

- 50 OS threads (Go runtime plus netstack workers, grows sub-linearly)
- 159 file descriptors, i.e. roughly one UDP socket per tunnel plus listeners

Set `LimitNOFILE` generously; the shipped systemd unit uses 65535.

## Tunnel setup time

- WireGuard handshake to a reachable server: **0.3–3.0 s**, typically ~1.6 s
- 30 tunnels pre-opened concurrently: ~300 ms wall clock
- 6 slots probed with concurrency 3: 5 s total

## How many unique exit IPs a bundle really provides

Measured against a 532-slot Mullvad bundle (device "Fast Pike"), sweeping the
whole catalog at `-concurrency 8` with no pacing:

```text
probed          532 slots in 3m44s
reachable       456
failed           76
unique IPs      456      <- one distinct exit IP per reachable slot
duplicates        0
distinct /24s   227
```

Two results matter here.

**There is no IP sharing.** Every reachable slot exited from its own address:
456 slots, 456 distinct IPs, ratio 1.00. The common assumption that a provider
multiplexes many servers behind one exit address did not hold for this bundle, so
`uniq=` batches can be as large as the number of *reachable* slots.

**The 76 failures were self-inflicted, not dead servers.** Cross-checking every
slot against Mullvad's live relay list (`api.mullvad.net/www/relays/wireguard/`)
showed all 532 still active, with matching public keys and endpoint addresses.
Ordering the results by completion time explains what actually happened:

```text
failure rate by decile of completion order
  0- 40%    0/212
 40- 60%    4/107
 60- 70%   11/53   ########
 70- 80%    6/53   ####
 80- 90%   24/53   ##################
 90-100%   31/54   ######################
```

The first 219 consecutive slots succeeded, then failures grew steadily. Shortly
afterwards *every* slot failed to handshake, including ones that had just worked,
and a repeat sweep from a second host with direct internet access returned
0/532. Nothing recovered within ten minutes.

That is a **provider-side handshake rate limit applied per device key**, not a
property of individual relays. ICMP to the affected relays kept working
throughout, and the key's tunnels were the only thing affected — a second
Mullvad device on the same network kept running normally.

### Consequences

- The practical ceiling for this bundle is **at least 456 and plausibly all 532**
  distinct exit IPs, but it cannot be confirmed in one fast sweep.
- Sweep large catalogs with `-interval` (e.g. `-interval 2s -concurrency 2`),
  ideally split across several sessions, and expect a full 532-slot inventory to
  take hours rather than minutes.
- Do not treat a probe failure as evidence that a relay is dead. Re-probe later
  with `-slots-file` before writing a slot off.
- Serving traffic is unaffected by this: the pool opens a tunnel only when a
  request needs one, and `max_active` keeps the handshake rate low. The limit is
  a bulk-measurement problem, not a runtime one.

## Sizing guidance

A container with **1 vCPU and 1.5–2 GiB RAM** can hold the entire 532-slot
catalog open. There is no need for one container per exit, nor for network
namespaces: the limiting factor is memory per open tunnel, and it is small.

Start with `max_active: 25`, watch RSS and the `open_tunnels` gauge in
`/v1/stats`, then raise it. Keep in mind:

- Throughput is userspace, so a single tunnel is slower than kernel WireGuard.
  This is a trade for isolation and zero host configuration.
- CPU scales with traffic, not with idle tunnel count. Idle tunnels only send a
  keepalive every 25 s.
- The number of slots is an upper bound on distinct exit IPs. Run
  `global-egress probe` to measure the real number before promising `uniq=`
  batches of a given size.
