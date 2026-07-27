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
