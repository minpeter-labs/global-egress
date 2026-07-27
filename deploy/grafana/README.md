# Grafana dashboard

`global-egress.json` — UID `global-egress`, title **Global Egress Proxy**, 12 panels.

It expects two things:

1. Prometheus scraping the guest's `node_exporter`, which also serves the textfile
   metrics written by `global-egress-collector`.
2. The scrape job carrying a `job` label. The dashboard has a `job` variable that
   defaults to `global-egress`, so a different job name needs no panel edits.

The datasource is a **variable**, not a fixed UID. That is deliberate: a Grafana
datasource UID is instance-specific, and a dashboard that hardcodes one silently
shows empty panels everywhere else.

## Prometheus job

```yaml
  - job_name: global-egress
    scrape_interval: 30s
    scrape_timeout: 10s
    static_configs:
      - targets: ['10.0.0.30:9100']
        labels: {instance: global-egress}
```

Let the scrape target own `instance`; do not also emit it from the collector, or
Prometheus renames the collector's copy to `exported_instance` and table joins break.

## Collector

The service exposes JSON, not Prometheus text, so a small loop translates it. See
[`../collector/global-egress-collector`](../collector/global-egress-collector).

```text
global-egress-collector  (60 s loop, read-only GETs against the control API)
  -> /var/lib/node_exporter/textfile_collector/global_egress.prom   (atomic replace)
node_exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
```

Series it produces:

| Series | Meaning |
|---|---|
| `global_egress_up` | control API answered |
| `global_egress_entry_open{entry,region}` | one row per entry tunnel |
| `global_egress_slots` | exits in the catalogue |
| `global_egress_slots_with_known_ip`, `global_egress_unique_public_ips` | inventory coverage |
| `global_egress_entries`, `global_egress_entries_open` | entry counts |
| `global_egress_active_leases`, `global_egress_max_concurrent_conns` | connection load against the cap |
| `global_egress_new_tunnels_used`, `global_egress_new_tunnel_budget` | key associations against the rate budget |
| `global_egress_acquisitions`, `global_egress_failures`, `global_egress_rotations`, `global_egress_reports`, `global_egress_refused_busy` | counters |
| `global_egress_sticky_sessions`, `global_egress_unique_batches` | live policy state |

The collector only ever performs GETs. Never call rotate, report or probe from
monitoring: a monitor that changes the thing it measures is worse than no monitor.

## Install

**File provisioning** (survives restarts, cannot be edited away by accident):

```sh
install -m 0644 deploy/grafana/global-egress.json \
  /opt/monitoring/grafana/dashboards/homelab/global-egress.json
docker restart grafana
```

**API import** (no restart, but the dashboard becomes editable and unmanaged):

```sh
jq '{dashboard: ., overwrite: true, folderId: 0}' deploy/grafana/global-egress.json \
  | curl -sS -u admin:PASSWORD -H 'Content-Type: application/json' \
      -d @- http://grafana.example.internal/api/dashboards/db
```

## Gotchas worth knowing

- **Two files with the same `uid` in a provisioning directory** make Grafana refuse
  DB writes and every panel renders as an empty titled frame — no error, no spinner.
  Check for duplicates before dropping a file in.
- **A provisioned dashboard rejects API overwrite** (`400: Cannot save provisioned
  dashboard`). Remove the file and restart Grafana first if you want to import.
- **Panels empty but the target is up?** Query the metric name against the Prometheus
  API directly. Every expression in this dashboard was validated that way; if one
  returns nothing, the collector or the job label is the suspect, not the panel.
