# Grafana dashboard

`global-egress.json` — UID `global-egress`, title **Global Egress Proxy**, 23 visual panels grouped under 4 section rows.

The layout follows the operator's scan path:

1. **Overview** — service state, request success rate, p95 setup latency, entry availability, and bounded capacity.
2. **Traffic & routing** — throughput, failure reasons, entry quality, and tunnel setup latency.
3. **Distribution & inventory** — requested versus selected countries, fallback rate, and exit coverage.
4. **Workload & host** — sessions, separate CPU and memory trends, network throughput, and scrape health.

## Health semantics

The aggregate status is intentionally stricter than process availability:

- **DOWN** — the control API is unavailable.
- **DEGRADED** — the API is available, but rolling 15-minute request success is
  below 90% or request setup p95 exceeds 2.5 seconds.
- **UP** — the API is available and both request SLOs are within those bounds.

Status, success rate, request p95, and entry p95 use the same rolling 15-minute
window. This lets the dashboard recover after a transient startup failure
instead of keeping one old failure in the process-lifetime counters until the
next restart. Success from 90% through 99% remains an orange warning; below 90%
is the red critical band that drives `DEGRADED`.

The request histogram has an explicit `2.5` second bucket, so the strict
`p95 > 2.5s` boundary means more than 5% of successful request setups exceeded
that bucket. The p95 panels use green below 1 second, warning from 1 second, and
critical from 2.5 seconds. Tunnel setup latency is tracked separately and does
not use the request threshold.

## Native visualizations

The dashboard intentionally uses only built-in Grafana panels:

| Visualization | Used for | Why |
|---|---|---|
| Stat | service state, success/fallback rates, p95 latency, capacities, and transferred bytes | Immediate state, compact ratios, or cumulative totals |
| Gauge | entry availability | It has a meaningful 0–100% range and outage thresholds |
| State timeline | entry tunnel state and collector/scrape health | Binary state duration matters more than line interpolation |
| Time series | request rates, throughput, sessions, and guest resources | Trends and correlated changes matter |
| Bar gauge | requested/selected country rankings, failure reasons, entry quality, tunnel latency, and exit inventory | Compact comparison of multiple current categories |

Canvas, geomap, node graph, and status history were not used. They would add
manual layout, require coordinates or topology data the collector does not
export, or duplicate the clearer state-timeline view.

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

The service exposes its detailed request and tunnel metrics as Prometheus text,
while the collector still translates the existing JSON inventory endpoints. See
[`../collector/global-egress-collector`](../collector/global-egress-collector).

```text
global-egress-collector  (60 s loop, read-only GETs against the control API)
  -> /var/lib/node_exporter/textfile_collector/global_egress.prom   (atomic replace)
node_exporter --collector.textfile.directory=/var/lib/node_exporter/textfile_collector
```

Point it at the control API through the environment, not by editing the script —
otherwise every deployment carries a private diff:

```sh
install -m 0755 deploy/collector/global-egress-collector /usr/local/bin/
install -m 0755 deploy/collector/global-egress-metrics.openrc /etc/init.d/global-egress-metrics
install -m 0644 deploy/collector/global-egress-metrics.confd /etc/conf.d/global-egress-metrics
# then edit CONTROL in /etc/conf.d/global-egress-metrics
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
| `global_egress_bytes_sent_total`, `global_egress_bytes_received_total` | payload relayed, counted at the proxy |
| `global_egress_country_acquisitions_total{country}` | successful exit selections by country |
| `global_egress_request_results_total{result,country,entry}` | completed proxy requests by bounded outcome |
| `global_egress_request_duration_seconds{result,country,entry}` | request setup duration histogram |
| `global_egress_requested_country_total{country}`, `global_egress_selected_country_total{country}` | requested policy versus actual selected exit country |
| `global_egress_country_fallback_total{requested,selected}` | selected country differed from a single requested country |
| `global_egress_payload_bytes_total{direction,country,entry}` | relayed payload attributed to selected country and entry |
| `global_egress_tunnel_opens_total{role,result}` | WireGuard entry/direct tunnel open outcomes |
| `global_egress_tunnel_open_duration_seconds{role,result}` | WireGuard setup and handshake duration histogram |
| `global_egress_entry_bytes_sent_total{entry,region}`, `..._received_total{entry,region}` | the same, per entry tunnel |

Counting bytes at the proxy rather than at the interface is deliberate: proxied
traffic crosses the guest NIC twice, once from the client and once inside the
tunnel, so `node_network_*` reads roughly double and cannot be attributed to an exit
or an entry. Both views are on the dashboard; they are expected to disagree.

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
