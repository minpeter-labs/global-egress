#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/api/v1" "$TMP/metrics"
printf '%s\n' '{
  "slots": 3,
  "acquisitions": 4
}' >"$TMP/api/v1/stats"
printf '%s\n' '{
  "count": 0,
  "entries": []
}' >"$TMP/api/v1/entries"
printf '%s\n' '{
  "countries": [
    {
      "country": "jp",
      "acquisitions": 3
    },
    {
      "country": "us",
      "acquisitions": 1
    }
  ]
}' >"$TMP/api/v1/country-acquisitions"
printf '%s\n' \
  '# HELP global_egress_request_results_total Completed proxy requests by result, selected country, and entry.' \
  '# TYPE global_egress_request_results_total counter' \
  'global_egress_request_results_total{result="success",country="jp",entry="entry-jp"} 3' \
  '# HELP global_egress_request_duration_seconds Request setup duration until upstream readiness.' \
  '# TYPE global_egress_request_duration_seconds histogram' \
  'global_egress_request_duration_seconds_bucket{result="success",country="jp",entry="entry-jp",le="0.25"} 3' \
  'global_egress_request_duration_seconds_bucket{result="success",country="jp",entry="entry-jp",le="+Inf"} 3' \
  'global_egress_request_duration_seconds_sum{result="success",country="jp",entry="entry-jp"} 0.375' \
  'global_egress_request_duration_seconds_count{result="success",country="jp",entry="entry-jp"} 3' \
  'global_egress_requested_country_total{country="jp"} 3' \
  'global_egress_selected_country_total{country="jp"} 3' \
  'global_egress_country_fallback_total{requested="us",selected="jp"} 1' \
  'global_egress_payload_bytes_total{direction="sent",country="jp",entry="entry-jp"} 128' \
  'global_egress_tunnel_opens_total{role="entry",result="success"} 1' \
  >"$TMP/api/v1/metrics"

CONTROL="file://$TMP/api" OUT_DIR="$TMP/metrics" \
  sh "$ROOT/deploy/collector/global-egress-collector" once

METRICS="$TMP/metrics/global_egress.prom"
grep -Fx 'global_egress_country_acquisitions_total{country="jp"} 3' "$METRICS"
grep -Fx 'global_egress_country_acquisitions_total{country="us"} 1' "$METRICS"
grep -Fx 'global_egress_request_results_total{result="success",country="jp",entry="entry-jp"} 3' "$METRICS"
grep -Fx 'global_egress_request_duration_seconds_count{result="success",country="jp",entry="entry-jp"} 3' "$METRICS"
grep -Fx 'global_egress_requested_country_total{country="jp"} 3' "$METRICS"
grep -Fx 'global_egress_selected_country_total{country="jp"} 3' "$METRICS"
grep -Fx 'global_egress_country_fallback_total{requested="us",selected="jp"} 1' "$METRICS"
grep -Fx 'global_egress_payload_bytes_total{direction="sent",country="jp",entry="entry-jp"} 128' "$METRICS"
grep -Fx 'global_egress_tunnel_opens_total{role="entry",result="success"} 1' "$METRICS"

mkfifo "$TMP/server-port"
python3 - "$TMP/server-port" <<'PY' &
import http.server
import sys

port_file = sys.argv[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/metrics":
            body = b'{"error":"not found"}\n'
            self.send_response(404)
        elif self.path == "/v1/stats":
            body = b'{"slots": 1}\n'
            self.send_response(200)
        elif self.path == "/v1/entries":
            body = b'{"count": 0, "entries": []}\n'
            self.send_response(200)
        else:
            body = b'{"countries": []}\n'
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="utf-8") as output:
    output.write(f"{server.server_port}\n")
server.serve_forever()
PY
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT
read -r SERVER_PORT <"$TMP/server-port"
mkdir "$TMP/error-metrics"
CONTROL="http://127.0.0.1:$SERVER_PORT" OUT_DIR="$TMP/error-metrics" \
  sh "$ROOT/deploy/collector/global-egress-collector" once
grep -Fx '# global-egress extended metrics unavailable' "$TMP/error-metrics/global_egress.prom"
if grep -Fq '{"error":"not found"}' "$TMP/error-metrics/global_egress.prom"; then
  echo "HTTP error body leaked into Prometheus output" >&2
  exit 1
fi

jq -e '
  .panels[]
  | select(.id == 23)
  | .targets[0].expr == "topk(8, sum by (country) (global_egress_selected_country_total{job=\"$job\"}))"
' "$ROOT/deploy/grafana/global-egress.json"

jq -e '
  .version == 17
  and (.panels | length) == 27
  and ([.panels[] | select(.type == "row") | .title] == [
    "Overview",
    "Traffic & routing",
    "Distribution & inventory",
    "Workload & host"
  ])
  and ([.panels[] | select(.id >= 1 and .id <= 5) | .title] == [
    "Status",
    "Success rate",
    "p95 setup latency",
    "Entry health",
    "Connections"
  ])
  and ([.panels[] | select(.id >= 1 and .id <= 5) | .gridPos] == [
    {"h":5,"w":8,"x":0,"y":1},
    {"h":5,"w":8,"x":8,"y":1},
    {"h":5,"w":8,"x":16,"y":1},
    {"h":5,"w":8,"x":0,"y":6},
    {"h":5,"w":8,"x":8,"y":6}
  ])
  and (.panels[] | select(.id == 40) | .title == "Tunnel budget" and .gridPos == {"h":5,"w":8,"x":16,"y":6})
  and ([.panels[] | select(.type == "row") | .gridPos.y] == [0, 11, 33, 49])
  and (.panels[] | select(.id == 2) | .targets[0].expr | contains("global_egress_request_results_total"))
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("global_egress_request_results_total"))
  and (.panels[] | select(.id == 1) | .targets[0].expr | contains("> bool 2.5"))
  and (.panels[] | select(.id == 1) | .description | contains("2.5 seconds"))
  and (.panels[] | select(.id == 1) | .fieldConfig.defaults.mappings[2].options["2"].text == "DEGRADED")
  and (.panels[] | select(.id == 3) | .targets[0].expr | contains("global_egress_request_duration_seconds_bucket"))
  and (.panels[] | select(.id == 3) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 3) | .fieldConfig.defaults.thresholds.steps[-1].value == 2.5)
  and (.panels[] | select(.id == 6) | .type == "state-timeline")
  and (.panels[] | select(.id == 6) | .targets[0].legendFormat == "{{entry}}")
  and (.panels[] | select(.id == 6) | .targets[0].expr | contains("entry=~\".*[A-Za-z0-9].*\""))
  and ([.panels[] | select(.id == 22) | .targets[].expr] | all(contains("entry=~\".*[A-Za-z0-9].*\"")))
  and (.panels[] | select(.id == 8) | .type == "bargauge")
  and (.panels[] | select(.id == 12) | .type == "state-timeline")
  and ([.panels[] | select(.id == 12) | .targets[].legendFormat] == ["node scrape", "control API"])
  and (.panels[] | select(.id == 23) | .type == "bargauge")
  and (.panels[] | select(.id == 42) | .targets[0].expr | contains("global_egress_requested_country_total"))
  and (.panels[] | select(.id == 43) | .targets[0].expr | contains("global_egress_country_fallback_total"))
  and (.panels[] | select(.id == 43) | .targets[0].expr | contains("or vector(0)"))
  and (.panels[] | select(.id == 43) | .targets[0].expr | contains("country!~\"any|multiple\""))
  and (.panels[] | select(.id == 44) | .targets[0].expr | contains("global_egress_request_results_total"))
  and (.panels[] | select(.id == 45) | .targets[0].expr | contains("global_egress_request_duration_seconds_bucket"))
  and (.panels[] | select(.id == 45) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 45) | .fieldConfig.defaults.color.mode == "thresholds")
  and (.panels[] | select(.id == 45) | .fieldConfig.defaults.thresholds.steps[-1].value == 2.5)
  and (.panels[] | select(.id == 47) | .targets[0].expr | contains("global_egress_tunnel_open_duration_seconds_bucket"))
  and (.panels[] | select(.id == 47) | .targets[0].expr | contains("rate(") | not)
  and (.panels[] | select(.id == 46) | .title == "Memory usage")
  and (.panels[] | select(.id == 9) | .title == "Session state")
  and (.panels[] | select(.id == 10) | .title == "CPU usage")
  and (.panels[] | select(.id == 11) | .title == "Network I/O")
' "$ROOT/deploy/grafana/global-egress.json"
