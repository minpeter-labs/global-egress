# cmd/global-egress

The binary: flag parsing, subcommand dispatch, and every seam that joins a
provider, the config and the pool. Package `main`, no internal state of its own.

## WHERE TO LOOK

| Task | File |
|---|---|
| Subcommand dispatch, `buildVersion`, usage text | `main.go` |
| Listener + pool startup, `buildSlots`, `poolOptionsFrom` | `serve.go` |
| `import`, `inspect`, `probe` | `catalog_cmds.go` |
| Entry name resolution, `entries.auto` region spread | `entries.go` |
| `relays` (Mullvad list inspect/refresh) | `relays_cmd.go` |
| `nordvpn` list rendering + key file handling | `nordvpn_cmd.go` |
| Owned-directory catalog writes | `nordvpn_catalog.go` |

## SEAMS

- `exitsFromRelays` (`serve.go`) is the only place a `mullvad.Relay` becomes a
  `pool.ExitSpec`. A third provider adds a sibling function here, not a branch in
  the pool.
- `poolOptionsFrom` (`serve.go`) is the only config-to-pool mapping.
  `wiring_test.go` compares both ends field by field, because a limit added to the
  config and the pool but forgotten here silently disables itself while every unit
  test keeps passing. Add the new field to that test.
- `buildSlots` decides mode: `wireguard` turns the whole catalog into slots;
  `relay-socks` takes exits from the relay list and uses the catalog only for
  entries.

## CONVENTIONS

- Every subcommand takes `newFlagSet(name)` so `-h` output stays uniform, and
  returns an error rather than exiting; `main` handles exit codes and swallows
  `context.Canceled`.
- Generated catalog directories are *owned*: `writeCatalog` stages a complete
  snapshot in a sibling temp dir, refuses a non-empty directory without a valid
  `.global-egress-nordvpn` manifest, refuses one holding files outside the
  manifest, then swaps with rollback. Never write into a shared catalog directory
  in place, and give each provider its own directory.
- Key material and rendered `.conf` files are written 0600 through a temp file plus
  rename; staging dirs are 0700.
- Provider-side failures report `(%T)` only, no paths or endpoints
  (`nordvpn_catalog.go`, `nordvpn_cmd.go`).
- `catalogFileName` encodes inner city hyphens as `_` so the catalog loader can
  recover a multi-word city from the name, and rejects anything with a separator or
  `..`.

## NOTES

- `version` is `-ldflags`-injected; without it `buildVersion` falls back to the
  toolchain's VCS stamp. Keep both paths working.
- Which NordVPN servers are usable is decided in `internal/nordvpn`
  (`List.Usable()`), not here. This package only renders what it is handed.
