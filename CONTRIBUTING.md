# Contributing

## Local development

```sh
make check   # gofmt, go vet, go test
make build   # ./bin/global-egress
```

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
