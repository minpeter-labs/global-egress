# internal/pool

Owns every egress slot: tunnels, health, measured public IP, and the selection
policy. Largest and most concurrent package here (~5000 lines incl. tests).

## WHERE TO LOOK

| Task | File |
|---|---|
| Selection, reservations, sessions, batches, budgets | `pool.go` (1475 lines) |
| Entry tunnel health, latency EWMA, entry ordering | `entry.go` |
| Public-IP measurement, `Probe`, inventory JSON, housekeeping | `inventory.go` |
| `Spec` / `ExitSpec` / `Kind`, `Dialer` interface | `spec.go` |
| Counter and histogram state | `metrics.go`, `metrics_snapshot.go` |

## INVARIANTS

- **Reserve before dialling.** `pick` returns an `acquisitionReservation` that
  holds the slot, its session name, its batch IP *and* connection capacity before
  the lock is released. A failed dial calls `rollbackAcquisition`; success calls
  `commitAcquisitionLocked`. Concurrent `Acquire` calls must not both pass a limit.
- **`pendingLeases` + `pendingTunnelOpens` + `probeTunnels` count against limits.**
  Anything that will occupy capacity is reserved while `mu` is held, not after.
- `uniq=` and `not=` require a measurement newer than `IPRefreshInterval`
  (`eligibleLocked`); a stale or unknown IP fails closed rather than weakening the
  distinctness guarantee. `setPublicIPLocked` backfills a new measurement into
  every live batch that consumed the slot.
- Batch rollback checks identity, not just the name: `rollbackBatchLocked` compares
  the reservation's `*batch` against `p.batches[name]` and bails when they differ,
  so an expired request cannot release a newer batch that reused the name.
- **Entries are blamed for entry faults.** `NoteDialFailure` routes any failure on
  a leased entry to `noteEntryFailure` unless it is a `socksdial.ErrDestination`
  refusal, which proves the entry path worked and belongs to the exit.
  `entryFailureThreshold` (3) consecutive failures disable the entry with
  exponential backoff (capped at 10m) and drop its tunnel so the next use
  re-handshakes. Without this, a dead entry disables the catalogue exit by exit.
- The new-tunnel budget gates every tunnel *opening* — WireGuard slots
  (`ensureOpen`), entries (`ensureEntryOpen`), and probes (`probeDialer`) all call
  `reserveTunnelOpenLocked`, and `commitTunnelOpen` charges it before dialling
  because a failed handshake spends the same provider quota. What it does not gate
  is *selecting* a relay-socks slot, which opens nothing
  (`TestTunnelBudgetDoesNotGateRelaySlots` vs `TestWireGuardSlotsStillGatedByBudget`).
- `slotState.ready()` is kind-aware: relay-socks slots are ready without a tunnel.
- `Close` sets `closing`, tears tunnels down, cancels `baseCtx`, then waits on
  `wg`. Start background work only through `background()`, which refuses after
  close.

## CONVENTIONS

- `Locked` suffix = caller holds `p.mu`. No exceptions.
- Entry routing: `georoute` supplies a prior (`priorLatencyPerHop` 250ms), real
  samples smooth in at `ewmaAlpha` 0.3 and always win. `EntryExploreRate` tries the
  runner-up so alternatives keep being measured; tests pin behaviour with
  `DisableEntryExploration` and `Options.Rand`.
- Every `Acquire` failure has its own sentinel so callers can map it to a status
  code. Add one rather than reusing `ErrExhausted`.
- Metric labels are bounded: `normalizeMetricLabel` + `isCountryCode` keep
  cardinality from following client input.

## ANTI-PATTERNS

- No `time.Sleep` in new tests. Use a channel and `awaitTestEvent`
  (`reservation_test.go`); `lifecycle_test.go` is the one pre-existing exception.
- Do not log or embed addresses, hostnames or relay endpoints: use
  `redactedError`.
- Do not reach for `Acquire` inside probing paths; it deliberately prefers
  already-open tunnels. `Probe` has its own capacity accounting.
