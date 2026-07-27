# Contributing

## Local development

```sh
make check   # formatting, vet, lint, tests
make fmt     # rewrite with gofumpt + goimports
make lint    # golangci-lint
make build   # ./bin/global-egress
```

`make tools` installs the pinned `golangci-lint` into `$(go env GOPATH)/bin`; the
other targets call it as needed.

Formatting goes through `golangci-lint fmt`, which is configured in
`.golangci.yaml` to run **gofumpt** and **goimports**. gofumpt is a strict superset
of gofmt, so gofmt-clean is implied, and goimports keeps imports in three groups -
standard library, external, then this module. Using the one binary for both local
runs and CI means the two cannot drift apart.

CI runs three jobs in parallel: `lint` (golangci-lint plus the formatting diff),
`test` (build, tests, tests under the race detector) and `vulncheck`
(`govulncheck`).

There are no external services in the unit tests: WireGuard and SOCKS behaviour is
exercised against in-process fakes, and anything that would dial a provider is
arranged to fail before it opens a socket.

## Trying it against a real provider

You need a WireGuard configuration bundle. Put it somewhere outside the repository,
or in `.secrets/`, which is ignored:

```sh
./bin/global-egress inspect -catalog .secrets/bundle.zip
./bin/global-egress relays  -cache .local-state/relays.json
cp deploy/config.example.yaml config.local.yaml   # ignored by git
./bin/global-egress serve -config config.local.yaml
python3 scripts/verify.py
```

`scripts/entry-bench.py` compares candidate entry tunnels from wherever you run
it, which is the only reliable way to choose entries: the best entry depends on
where the service is deployed, not on where the exits are.

## Dependencies

```sh
make outdated    # only the modules this project actually builds against
make vulncheck   # govulncheck
```

`go list -m -u all` is not useful here: gvisor drags in containerd, Kubernetes and
gRPC through its module graph, and none of that is in the binary. `make outdated`
lists the real set.

`gvisor.dev/gvisor` is pinned by `wireguard-go` and should be left alone. Newer
snapshots have a `pkg/tcpip/stack` directory declaring two different packages, so
the build fails outright; there is a comment in `go.mod` saying so.

## Things to be careful about

**Never commit a bundle, a `.conf`, or a key.** `.gitignore` covers `*.zip`,
`*.conf` and `.secrets/`, but check `git status` before committing anyway.

**Do not bulk-probe a provider with one key.** Opening tunnels to hundreds of
relays in a few minutes looks like key sharing and can get the key blocked for
hours. `probe` has `-interval` for pacing, and the pool has a new-tunnel rate
budget; leave both in place. Details in [docs/capacity.md](docs/capacity.md).

**Keep the two guarantees honest.** `sess=` must return the same exit for a
session, and `uniq=` must never repeat a public IP within a batch. Both are
enforced against *measured* exit addresses, not relay names, because different
relays can share an address.
