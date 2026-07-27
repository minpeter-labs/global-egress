# Security

## Reporting

Please report suspected vulnerabilities privately through GitHub's
[security advisories](https://github.com/minpeter-labs/global-egress/security/advisories/new)
rather than in a public issue.

## What this project handles

The service reads a VPN provider's WireGuard bundle, which contains a **private
key**. Treat the catalog directory and any bundle archive as key material:

- the repository ignores `*.zip`, `*.conf` and `.secrets/`
- `global-egress import` writes configs with mode `0600` into a `0700` directory
- the shipped systemd unit uses `StateDirectoryMode=0700`
- logs record slot names, entry names and destinations, never key material

## Threat model

`global-egress` is meant for a trusted internal network. It is **not** hardened for
exposure to the internet, and it is **not** an anonymity tool.

- Bind the listeners to an internal address and set `access.allowed_clients`.
  An empty allow list means every host that can reach the port may use it.
- `access.password` is a single shared secret, not per-user identity. The proxy
  username carries the selection policy, so it cannot also carry an identity.
- The control API can rotate sessions and put exits on cooldown. Protect it with
  `access.control_token` if anything other than your own tooling can reach it.
- Destinations in private, loopback, link-local, CGNAT and multicast ranges are
  refused by default, so the proxy is not a route into the network hosting it. In
  `relay-socks` mode the destination is resolved at the exit relay, so a *name*
  that resolves into private space cannot be caught locally; literal private
  addresses are still refused.
- The VPN provider sees every tunnel, and the service logs which exit served which
  destination.

## Provider rate limits

Opening tunnels to many relays in a short time looks like key sharing and can get
a device key blocked for hours. The pool caps new tunnels per window and `probe`
supports pacing; leaving both in place protects the key. See
[docs/capacity.md](docs/capacity.md).
