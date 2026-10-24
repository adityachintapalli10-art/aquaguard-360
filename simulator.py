"""Send SIMULATED readings to a running AquaGuard server (demo / testing only).

    python simulator.py --server http://127.0.0.1:5000 --leak 04
    python simulator.py --spike S01-HOME-A

Uses the device keys in simulator_keys.json created by `seed.py --demo`.
"""
import argparse
import json
import random
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


def post(server, key, payload):
    req = urllib.request.Request(server.rstrip("/") + "/api/ingest", data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json", "X-API-Key": key})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return f"{e.code} {e.read().decode()[:120]}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://127.0.0.1:5000")
    ap.add_argument("--keys", default="simulator_keys.json")
    ap.add_argument("--interval", type=float, default=5, help="seconds between rounds")
    ap.add_argument("--leak", metavar="STREET_NO", help="e.g. 04: add 6 L/min extra to that street's inlet")
    ap.add_argument("--spike", metavar="DEVICE", help="send 40 L/min from this device")
    args = ap.parse_args()
    keys = json.load(open(args.keys))
    total = {name: 0.0 for name in keys}
    rng = random.Random()
    print("Sending SIMULATED data. Ctrl+C to stop.")
    while True:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        flows = {}
        for name in keys:
            if "INLET" in name:
                continue
            flows[name] = 40.0 if name == args.spike else (rng.uniform(2, 12) if rng.random() < 0.4 else 0.0)
        for name in keys:
            if "INLET" in name:
                street = name[:3]
                f = sum(v for k, v in flows.items() if k.startswith(street)) * 1.02
                if args.leak and street == f"S{int(args.leak):02d}":
                    f += 6.0
                flows[name] = f
        for name, f in flows.items():
            total[name] += f * args.interval / 60
            print(name, round(f, 2), "L/min ->", post(args.server, keys[name], {"ts": ts, "flow_lpm": round(f, 3), "total_l": round(total[name], 3)}))
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
