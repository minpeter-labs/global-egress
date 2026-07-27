#!/usr/bin/env python3
"""End-to-end check against a running global-egress instance.

Usage: scripts/verify.py [http://host:port] [http://control:port]

Every request goes through the proxy under test, so this doubles as a smoke test
of the whole path: policy parsing, slot selection, entry routing and relaying.
"""

import concurrent.futures
import json
import sys
import time
import urllib.request

PROXY = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:13128"
CONTROL = sys.argv[2] if len(sys.argv) > 2 else "http://127.0.0.1:18080"
CHECK_URL = "https://am.i.mullvad.net/json"


def through_proxy(policy: str, url: str = CHECK_URL, timeout: int = 45) -> dict:
    """Fetch url through the proxy using policy as the proxy username."""
    host = PROXY.removeprefix("http://")
    proxy_url = f"http://{policy}:x@{host}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
    )
    with opener.open(url, timeout=timeout) as response:
        return json.load(response)


def control(path: str) -> dict:
    with urllib.request.urlopen(f"{CONTROL}{path}", timeout=15) as response:
        return json.load(response)


def check_countries() -> bool:
    print("== country selection ==")
    ok = True
    for cc in ("jp", "de", "us", "br", "au", "se", "za"):
        try:
            data = through_proxy(f"cc={cc}")
            got = data["mullvad_exit_ip_hostname"]
            match = got.startswith(cc + "-")
            ok &= match
            print(f"  cc={cc:<3} {data['ip']:<18} {data['country']:<16} {got}"
                  f"{'' if match else '   <-- WRONG COUNTRY'}")
        except Exception as exc:  # noqa: BLE001 - report and continue
            ok = False
            print(f"  cc={cc:<3} FAILED: {exc}")
    return ok


def check_sticky() -> bool:
    print("\n== sticky session (same IP expected) ==")
    ips = []
    for _ in range(3):
        ips.append(through_proxy("sess=verify-1;ttl=300")["ip"])
    print(f"  {ips}")
    return len(set(ips)) == 1


def check_unique(count: int, workers: int) -> bool:
    print(f"\n== unique batch of {count} (concurrency {workers}) ==")
    started = time.monotonic()
    ips, errors = [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(through_proxy, "uniq=verify-batch") for _ in range(count)]
        for future in concurrent.futures.as_completed(futures):
            try:
                ips.append(future.result()["ip"])
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
    elapsed = time.monotonic() - started
    print(f"  responses {len(ips)}, distinct {len(set(ips))}, errors {len(errors)}")
    print(f"  {elapsed:.1f}s total -> {len(ips) / elapsed:.1f} new exit IPs/second")
    if errors:
        print(f"  first error: {errors[0]}")
    return len(ips) == count and len(set(ips)) == count


def show_entries() -> None:
    print("\n== entries and what has been learned ==")
    for entry in control("/v1/entries")["entries"]:
        latency = entry.get("latency_ms") or {}
        top = sorted(latency.items(), key=lambda kv: kv[1])[:6]
        summary = ", ".join(f"{cc}={ms}ms" for cc, ms in top) or "no samples yet"
        print(f"  {entry['id']:<16} {entry['region']:<14} open={entry['open']}")
        print(f"      measured: {summary}")


def show_stats() -> None:
    print("\n== stats ==")
    stats = control("/v1/stats")
    for key in ("slots", "entries", "entries_open", "open_tunnels", "new_tunnels_used",
                "unique_public_ips", "slots_with_known_ip", "acquisitions", "failures"):
        print(f"  {key:<22} {stats[key]}")


def main() -> int:
    results = {
        "countries": check_countries(),
        "sticky": check_sticky(),
        "unique": check_unique(count=20, workers=8),
    }
    show_entries()
    show_stats()

    print("\n== summary ==")
    for name, passed in results.items():
        print(f"  {name:<12} {'PASS' if passed else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
